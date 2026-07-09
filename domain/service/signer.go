package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

// SigningKey pairs a JWKS key id with an Ed25519 private key.
type SigningKey struct {
	Kid        string
	PrivateKey ed25519.PrivateKey
}

// AccessClaims is the exact claim set of a keysmith access JWT
// (master plan §5): sub, email, iss, aud, exp, iat, jti — nothing else.
type AccessClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// Signer mints and verifies access JWTs and serves the matching JWKS.
// keys[0] is the active signing key; all keys verify and appear in the JWKS,
// which is how rotation works: introduce the new key first, sign with it once
// consumers have refetched (master plan §5).
type Signer struct {
	keys []SigningKey
	byID map[string]ed25519.PublicKey
	jwks []byte
}

// NewSigner validates the key set and precomputes the JWKS document.
func NewSigner(keys []SigningKey) (*Signer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("signer: at least one signing key is required")
	}
	byID := make(map[string]ed25519.PublicKey, len(keys))
	for i, k := range keys {
		if k.Kid == "" {
			return nil, fmt.Errorf("signer: key %d has empty kid", i)
		}
		if len(k.PrivateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("signer: key %q has invalid Ed25519 private key length %d", k.Kid, len(k.PrivateKey))
		}
		if _, dup := byID[k.Kid]; dup {
			return nil, fmt.Errorf("signer: duplicate kid %q", k.Kid)
		}
		byID[k.Kid] = k.PrivateKey.Public().(ed25519.PublicKey)
	}

	jwks, err := buildJWKS(keys)
	if err != nil {
		return nil, err
	}
	return &Signer{keys: keys, byID: byID, jwks: jwks}, nil
}

// ParsePrivateKey decodes a base64 (standard encoding) Ed25519 key that is
// either a 32-byte seed or a 64-byte private key.
func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64 private key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("private key must be a %d-byte seed or %d-byte key, got %d bytes",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}

// MintAccessToken signs an access JWT for the user with the active key.
func (s *Signer) MintAccessToken(now time.Time, user *model.User, issuer, audience string, ttl time.Duration) (string, error) {
	active := s.keys[0]
	claims := AccessClaims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = active.Kid

	signed, err := token.SignedString(active.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// VerifyAccessToken validates signature (by kid), issuer, audience, and
// expiry with 30s leeway, returning the claims.
func (s *Signer) VerifyAccessToken(tokenString, issuer, audience string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, s.keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("verify access token: %w", err)
	}
	return claims, nil
}

func (s *Signer) keyFunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	pub, ok := s.byID[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return pub, nil
}

// JWKS returns the precomputed JWKS document with every valid public key.
func (s *Signer) JWKS() []byte {
	return s.jwks
}

// jwk is an RFC 7517 JSON Web Key for an Ed25519 public key (RFC 8037).
type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

func buildJWKS(keys []SigningKey) ([]byte, error) {
	doc := struct {
		Keys []jwkKey `json:"keys"`
	}{Keys: make([]jwkKey, 0, len(keys))}

	for _, k := range keys {
		pub := k.PrivateKey.Public().(ed25519.PublicKey)
		doc.Keys = append(doc.Keys, jwkKey{
			Kty: "OKP",
			Crv: "Ed25519",
			Alg: "EdDSA",
			Use: "sig",
			Kid: k.Kid,
			X:   base64.RawURLEncoding.EncodeToString(pub),
		})
	}

	jwks, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}
	return jwks, nil
}

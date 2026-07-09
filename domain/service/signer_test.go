package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

const (
	testIssuer   = "https://auth.test"
	testAudience = "forge"
)

func newTestSigner(t *testing.T, kids ...string) *Signer {
	t.Helper()
	keys := make([]SigningKey, 0, len(kids))
	for _, kid := range kids {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		keys = append(keys, SigningKey{Kid: kid, PrivateKey: priv})
	}
	s, err := NewSigner(keys)
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	return s
}

func testUser(t *testing.T) *model.User {
	t.Helper()
	return &model.User{ID: uuid.New(), Email: "sri@example.com"}
}

func TestSigner_MintVerifyRoundtrip(t *testing.T) {
	s := newTestSigner(t, "key-a")
	u := testUser(t)

	tok, err := s.MintAccessToken(time.Now(), u, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}

	claims, err := s.VerifyAccessToken(tok, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error: %v", err)
	}
	if claims.Subject != u.ID.String() {
		t.Errorf("sub = %q, want %q", claims.Subject, u.ID)
	}
	if claims.Email != u.Email {
		t.Errorf("email = %q, want %q", claims.Email, u.Email)
	}
	if claims.ID == "" {
		t.Error("jti is empty")
	}
}

func TestSigner_VerifyRejections(t *testing.T) {
	s := newTestSigner(t, "key-a")
	u := testUser(t)
	now := time.Now()

	valid, err := s.MintAccessToken(now, u, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}
	expired, err := s.MintAccessToken(now.Add(-time.Hour), u, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}
	fromStranger, err := newTestSigner(t, "key-a").MintAccessToken(now, u, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}

	tests := []struct {
		name     string
		token    string
		issuer   string
		audience string
	}{
		{name: "wrong audience", token: valid, issuer: testIssuer, audience: "not-forge"},
		{name: "wrong issuer", token: valid, issuer: "https://evil.test", audience: testAudience},
		{name: "expired beyond leeway", token: expired, issuer: testIssuer, audience: testAudience},
		{name: "same kid different key", token: fromStranger, issuer: testIssuer, audience: testAudience},
		{name: "garbage", token: "not.a.jwt", issuer: testIssuer, audience: testAudience},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.VerifyAccessToken(tt.token, tt.issuer, tt.audience); err == nil {
				t.Error("VerifyAccessToken() succeeded, want error")
			}
		})
	}
}

func TestSigner_ExpiryLeeway(t *testing.T) {
	s := newTestSigner(t, "key-a")
	u := testUser(t)

	// Expired 10s ago — inside the 30s leeway, so still valid.
	tok, err := s.MintAccessToken(time.Now().Add(-15*time.Minute-10*time.Second), u, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}
	if _, err := s.VerifyAccessToken(tok, testIssuer, testAudience); err != nil {
		t.Errorf("VerifyAccessToken() inside leeway error: %v", err)
	}
}

func TestSigner_UnknownKid(t *testing.T) {
	minter := newTestSigner(t, "key-old")
	verifier := newTestSigner(t, "key-new")
	u := testUser(t)

	tok, err := minter.MintAccessToken(time.Now(), u, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}
	_, err = verifier.VerifyAccessToken(tok, testIssuer, testAudience)
	if err == nil || !strings.Contains(err.Error(), "unknown kid") {
		t.Errorf("VerifyAccessToken() error = %v, want unknown kid", err)
	}
}

func TestSigner_SignsWithFirstKey(t *testing.T) {
	s := newTestSigner(t, "active", "previous")
	u := testUser(t)

	tok, err := s.MintAccessToken(time.Now(), u, testIssuer, testAudience, time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, &AccessClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified() error: %v", err)
	}
	if kid := parsed.Header["kid"]; kid != "active" {
		t.Errorf("kid = %v, want active", kid)
	}
}

// TestSigner_JWKSParsesWithJWX is the Phase 2 acceptance check: the JWKS
// document must round-trip through jwx and verify a minted token.
func TestSigner_JWKSParsesWithJWX(t *testing.T) {
	s := newTestSigner(t, "key-a", "key-b")
	u := testUser(t)

	set, err := jwk.Parse(s.JWKS())
	if err != nil {
		t.Fatalf("jwk.Parse(JWKS()) error: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("JWKS has %d keys, want 2", set.Len())
	}

	key, ok := set.LookupKeyID("key-a")
	if !ok {
		t.Fatal("kid key-a not found in JWKS")
	}
	var pub ed25519.PublicKey
	if err := jwk.Export(key, &pub); err != nil {
		t.Fatalf("jwk.Export() error: %v", err)
	}

	// The jwx-extracted public key must verify a token minted by the signer.
	tok, err := s.MintAccessToken(time.Now(), u, testIssuer, testAudience, time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken() error: %v", err)
	}
	claims := &AccessClaims{}
	_, err = jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	if err != nil {
		t.Fatalf("verify with jwx-extracted key: %v", err)
	}
	if claims.Subject != u.ID.String() {
		t.Errorf("sub = %q, want %q", claims.Subject, u.ID)
	}
}

func TestNewSigner_Validation(t *testing.T) {
	if _, err := NewSigner(nil); err == nil {
		t.Error("NewSigner(nil) succeeded, want error")
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := NewSigner([]SigningKey{{Kid: "a", PrivateKey: priv}, {Kid: "a", PrivateKey: priv}}); err == nil {
		t.Error("NewSigner() with duplicate kid succeeded, want error")
	}
	if _, err := NewSigner([]SigningKey{{Kid: "a", PrivateKey: priv[:10]}}); err == nil {
		t.Error("NewSigner() with truncated key succeeded, want error")
	}
}

func TestParsePrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// 64-byte private key and 32-byte seed must produce the same key.
	full, err := ParsePrivateKey(b64(priv))
	if err != nil {
		t.Fatalf("ParsePrivateKey(64-byte) error: %v", err)
	}
	seed, err := ParsePrivateKey(b64(priv.Seed()))
	if err != nil {
		t.Fatalf("ParsePrivateKey(32-byte seed) error: %v", err)
	}
	if !full.Equal(seed) {
		t.Error("seed-derived key differs from full key")
	}

	if _, err := ParsePrivateKey("!!!not-base64!!!"); err == nil {
		t.Error("ParsePrivateKey(garbage) succeeded, want error")
	}
	if _, err := ParsePrivateKey(b64(priv[:16])); err == nil {
		t.Error("ParsePrivateKey(wrong length) succeeded, want error")
	}
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

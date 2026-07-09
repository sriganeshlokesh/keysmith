package authkit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testIssuer   = "https://auth.test"
	testAudience = "forge"
	testSubject  = "3f6c2f0e-5cbe-49bb-8f4d-2b8f97f1a111"
	testEmail    = "sri@example.com"
)

// newKeypair generates an Ed25519 keypair as jwk keys with the given kid.
func newKeypair(t *testing.T, kid string) (privJWK, pubJWK jwk.Key, rawPub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privJWK, err = jwk.Import(priv)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	pubJWK, err = jwk.PublicKeyOf(privJWK)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	return privJWK, pubJWK, pub
}

type mintOpts struct {
	issuer  string
	subject string
	iat     time.Time
	exp     time.Time
}

func mint(t *testing.T, priv jwk.Key, audience string, o mintOpts) string {
	t.Helper()
	if o.issuer == "" {
		o.issuer = testIssuer
	}
	if o.subject == "" {
		o.subject = testSubject
	}
	if o.iat.IsZero() {
		o.iat = time.Now()
	}
	if o.exp.IsZero() {
		o.exp = o.iat.Add(15 * time.Minute)
	}
	tok, err := jwt.NewBuilder().
		Issuer(o.issuer).
		Audience([]string{audience}).
		Subject(o.subject).
		IssuedAt(o.iat).
		Expiration(o.exp).
		Claim("email", testEmail).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), priv))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// jwksServer serves a mutable JWKS document and counts fetches.
type jwksServer struct {
	mu      sync.Mutex
	keys    []jwk.Key
	fetches int
	ts      *httptest.Server
}

func newJWKSServer(t *testing.T, keys ...jwk.Key) *jwksServer {
	t.Helper()
	s := &jwksServer{keys: keys}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetches++
		set := jwk.NewSet()
		for _, k := range s.keys {
			if err := set.AddKey(k); err != nil {
				t.Errorf("add key: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *jwksServer) setKeys(keys ...jwk.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = keys
}

func (s *jwksServer) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func newTestVerifier(t *testing.T, jwksURL string, minRefresh time.Duration) *Verifier {
	t.Helper()
	v, err := NewVerifier(t.Context(), Config{
		JWKSURL:            jwksURL,
		Issuer:             testIssuer,
		Audience:           testAudience,
		MinRefreshInterval: minRefresh,
		Logger:             slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}
	return v
}

// TestVerify_Table is the Phase 5 acceptance matrix: expired token, wrong
// aud, wrong iss, unknown kid, garbage token, clock skew boundary.
func TestVerify_Table(t *testing.T) {
	priv, pub, _ := newKeypair(t, "key-1")
	strangerPriv, _, _ := newKeypair(t, "key-unknown")
	srv := newJWKSServer(t, pub)
	now := time.Now()

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:  "valid",
			token: mint(t, priv, testAudience, mintOpts{}),
		},
		{
			name:    "expired beyond leeway",
			token:   mint(t, priv, testAudience, mintOpts{iat: now.Add(-time.Hour), exp: now.Add(-time.Minute)}),
			wantErr: true,
		},
		{
			name: "expired within 30s leeway (clock skew boundary)",
			// exp 10s in the past — inside the 30s acceptable skew.
			token: mint(t, priv, testAudience, mintOpts{iat: now.Add(-15 * time.Minute), exp: now.Add(-10 * time.Second)}),
		},
		{
			name:    "wrong audience",
			token:   mint(t, priv, "not-forge", mintOpts{}),
			wantErr: true,
		},
		{
			name:    "wrong issuer",
			token:   mint(t, priv, testAudience, mintOpts{issuer: "https://evil.test"}),
			wantErr: true,
		},
		{
			name:    "unknown kid",
			token:   mint(t, strangerPriv, testAudience, mintOpts{}),
			wantErr: true,
		},
		{
			name:    "garbage token",
			token:   "not.a.jwt",
			wantErr: true,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// High min-refresh: unknown kids must fail without hammering the
			// endpoint. Fresh verifier per case keeps refresh state isolated.
			v := newTestVerifier(t, srv.ts.URL, time.Hour)
			id, err := v.Verify(t.Context(), tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Verify() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() error: %v", err)
			}
			if id.UserID != testSubject {
				t.Errorf("UserID = %q, want %q", id.UserID, testSubject)
			}
			if id.Email != testEmail {
				t.Errorf("Email = %q, want %q", id.Email, testEmail)
			}
		})
	}
}

// TestVerify_RefreshOnUnknownKid simulates key rotation: a token signed by a
// key published after the initial JWKS fetch verifies via a forced refresh.
func TestVerify_RefreshOnUnknownKid(t *testing.T) {
	oldPriv, oldPub, _ := newKeypair(t, "old")
	newPriv, newPub, _ := newKeypair(t, "new")

	srv := newJWKSServer(t, oldPub)
	v := newTestVerifier(t, srv.ts.URL, time.Nanosecond) // allow immediate forced refresh

	// Sanity: old key verifies from the initial fetch.
	if _, err := v.Verify(t.Context(), mint(t, oldPriv, testAudience, mintOpts{})); err != nil {
		t.Fatalf("Verify(old key) error: %v", err)
	}

	// Rotate: publish the new key, then present a token signed by it.
	srv.setKeys(oldPub, newPub)
	id, err := v.Verify(t.Context(), mint(t, newPriv, testAudience, mintOpts{}))
	if err != nil {
		t.Fatalf("Verify(new key after rotation) error: %v", err)
	}
	if id.UserID != testSubject {
		t.Errorf("UserID = %q, want %q", id.UserID, testSubject)
	}
}

// TestVerify_RefreshRateLimited proves the forced refresh respects the
// minimum interval instead of refetching for every unknown kid.
func TestVerify_RefreshRateLimited(t *testing.T) {
	_, pub, _ := newKeypair(t, "known")
	strangerPriv, _, _ := newKeypair(t, "stranger")

	srv := newJWKSServer(t, pub)
	v := newTestVerifier(t, srv.ts.URL, time.Hour)
	after := srv.fetchCount()

	for range 5 {
		if _, err := v.Verify(t.Context(), mint(t, strangerPriv, testAudience, mintOpts{})); err == nil {
			t.Fatal("Verify(stranger) succeeded, want error")
		}
	}
	if got := srv.fetchCount(); got != after {
		t.Errorf("unknown kids triggered %d extra fetches within the interval, want 0", got-after)
	}
}

// TestDevMode_Offline is the Phase 5 acceptance check for dev mode: a static
// public key, zero network.
func TestDevMode_Offline(t *testing.T) {
	priv, _, rawPub := newKeypair(t, "dev-kid")

	v, err := NewVerifier(t.Context(), Config{
		Issuer:    testIssuer,
		DevKeyB64: base64.StdEncoding.EncodeToString(rawPub),
		DevKid:    "dev-kid",
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewVerifier(dev) error: %v", err)
	}

	id, err := v.Verify(t.Context(), mint(t, priv, testAudience, mintOpts{}))
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if id.UserID != testSubject || id.Email != testEmail {
		t.Errorf("identity = %+v", id)
	}

	// A different key must fail even in dev mode.
	otherPriv, _, _ := newKeypair(t, "dev-kid")
	if _, err := v.Verify(t.Context(), mint(t, otherPriv, testAudience, mintOpts{})); err == nil {
		t.Error("Verify(wrong dev key) succeeded, want error")
	}
}

func TestNewVerifier_Validation(t *testing.T) {
	ctx := context.Background()
	if _, err := NewVerifier(ctx, Config{JWKSURL: "http://x"}); err == nil {
		t.Error("NewVerifier without Issuer succeeded, want error")
	}
	if _, err := NewVerifier(ctx, Config{Issuer: testIssuer}); err == nil {
		t.Error("NewVerifier without JWKSURL or DevKey succeeded, want error")
	}
	if _, err := NewVerifier(ctx, Config{Issuer: testIssuer, DevKeyB64: "!!!"}); err == nil {
		t.Error("NewVerifier with garbage DevKeyB64 succeeded, want error")
	}
	if _, err := NewVerifier(ctx, Config{Issuer: testIssuer, DevKeyB64: base64.StdEncoding.EncodeToString([]byte("short"))}); err == nil {
		t.Error("NewVerifier with short DevKeyB64 succeeded, want error")
	}
	// Unreachable JWKS must fail at startup, not at first request. The cache
	// retries internally, so this is bounded by StartupTimeout.
	_, err := NewVerifier(ctx, Config{
		Issuer:         testIssuer,
		JWKSURL:        "http://127.0.0.1:1/jwks.json",
		StartupTimeout: time.Second,
		Logger:         slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Error("NewVerifier with unreachable JWKS succeeded, want startup error")
	}
}

func TestDevPublicKeyConstant(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(DevPublicKeyB64)
	if err != nil {
		t.Fatalf("DevPublicKeyB64 is not valid base64: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Errorf("DevPublicKeyB64 decodes to %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
}

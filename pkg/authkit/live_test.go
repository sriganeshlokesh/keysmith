package authkit

import (
	"os"
	"testing"
)

// TestLiveKeysmith verifies a real keysmith-minted token against a running
// keysmith instance — both via its live JWKS endpoint and, when the instance
// runs with ENV=local, via offline dev mode. Skipped unless configured:
//
//	AUTHKIT_LIVE_JWKS_URL=http://localhost:8080/.well-known/jwks.json \
//	AUTHKIT_LIVE_ISSUER=http://localhost:8080 \
//	AUTHKIT_LIVE_TOKEN=<access token from /auth/login> \
//	AUTHKIT_LIVE_DEV=1 go test -run TestLiveKeysmith -v .
func TestLiveKeysmith(t *testing.T) {
	jwksURL := os.Getenv("AUTHKIT_LIVE_JWKS_URL")
	issuer := os.Getenv("AUTHKIT_LIVE_ISSUER")
	token := os.Getenv("AUTHKIT_LIVE_TOKEN")
	if jwksURL == "" || issuer == "" || token == "" {
		t.Skip("AUTHKIT_LIVE_* not set; skipping live verification")
	}

	t.Run("via JWKS", func(t *testing.T) {
		v, err := NewVerifier(t.Context(), Config{JWKSURL: jwksURL, Issuer: issuer})
		if err != nil {
			t.Fatalf("NewVerifier() error: %v", err)
		}
		id, err := v.Verify(t.Context(), token)
		if err != nil {
			t.Fatalf("Verify() error: %v", err)
		}
		t.Logf("verified: user=%s email=%s", id.UserID, id.Email)

		if _, err := v.Verify(t.Context(), token+"tampered"); err == nil {
			t.Error("Verify(tampered) succeeded, want error")
		}
	})

	t.Run("dev mode offline", func(t *testing.T) {
		if os.Getenv("AUTHKIT_LIVE_DEV") == "" {
			t.Skip("AUTHKIT_LIVE_DEV not set (instance not using the dev keypair)")
		}
		v, err := NewVerifier(t.Context(), Config{Issuer: issuer, DevKeyB64: DevPublicKeyB64})
		if err != nil {
			t.Fatalf("NewVerifier(dev) error: %v", err)
		}
		id, err := v.Verify(t.Context(), token)
		if err != nil {
			t.Fatalf("Verify() offline error: %v", err)
		}
		t.Logf("verified offline: user=%s email=%s", id.UserID, id.Email)
	})
}

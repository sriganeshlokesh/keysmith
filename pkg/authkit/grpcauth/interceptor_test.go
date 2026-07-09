package grpcauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/sriganeshlokesh/keysmith/pkg/authkit"
)

const (
	testIssuer  = "https://auth.test"
	testSubject = "7f0a4c9e-1111-4f30-9d5e-aaaaaaaaaaaa"
)

func setup(t *testing.T) (grpc.UnaryServerInterceptor, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privJWK, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("import key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "grpc-kid"); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Audience([]string{authkit.Audience}).
		Subject(testSubject).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(15*time.Minute)).
		Claim("email", "sri@example.com").
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privJWK))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	v, err := authkit.NewVerifier(t.Context(), authkit.Config{
		Issuer:    testIssuer,
		DevKeyB64: base64.StdEncoding.EncodeToString(pub),
		DevKid:    "grpc-kid",
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}
	return UnaryInterceptor(v), string(signed)
}

func TestUnaryInterceptor(t *testing.T) {
	interceptor, validToken := setup(t)

	tests := []struct {
		name     string
		md       metadata.MD
		noMD     bool
		wantCode codes.Code
	}{
		{name: "valid token", md: metadata.Pairs("authorization", "Bearer "+validToken), wantCode: codes.OK},
		{name: "no metadata", noMD: true, wantCode: codes.Unauthenticated},
		{name: "missing authorization", md: metadata.MD{}, wantCode: codes.Unauthenticated},
		{name: "not bearer", md: metadata.Pairs("authorization", "Basic zzz"), wantCode: codes.Unauthenticated},
		{name: "invalid token", md: metadata.Pairs("authorization", "Bearer junk"), wantCode: codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			if !tt.noMD {
				ctx = metadata.NewIncomingContext(ctx, tt.md)
			}

			var gotUserID string
			handler := func(ctx context.Context, req any) (any, error) {
				gotUserID = authkit.UserID(ctx)
				return "ok", nil
			}
			_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("interceptor error: %v", err)
				}
				if gotUserID != testSubject {
					t.Errorf("UserID in handler = %q, want %q", gotUserID, testSubject)
				}
				return
			}
			if status.Code(err) != tt.wantCode {
				t.Errorf("code = %v, want %v", status.Code(err), tt.wantCode)
			}
			if gotUserID != "" {
				t.Error("handler ran despite rejection")
			}
		})
	}
}

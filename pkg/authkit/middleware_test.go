package authkit

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware(t *testing.T) {
	priv, _, rawPub := newKeypair(t, "mw-kid")
	v, err := NewVerifier(t.Context(), Config{
		Issuer:    testIssuer,
		DevKeyB64: base64.StdEncoding.EncodeToString(rawPub),
		DevKid:    "mw-kid",
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	var gotUserID, gotEmail string
	protected := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserID(r.Context())
		gotEmail = Email(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "valid token", authHeader: "Bearer " + mint(t, priv, testAudience, mintOpts{}), wantStatus: http.StatusOK},
		{name: "missing header", authHeader: "", wantStatus: http.StatusUnauthorized},
		{name: "not bearer", authHeader: "Basic dXNlcjpwdw==", wantStatus: http.StatusUnauthorized},
		{name: "empty bearer", authHeader: "Bearer ", wantStatus: http.StatusUnauthorized},
		{name: "invalid token", authHeader: "Bearer not.a.jwt", wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, gotEmail = "", ""
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK {
				if gotUserID != testSubject || gotEmail != testEmail {
					t.Errorf("context identity = %q/%q, want %q/%q", gotUserID, gotEmail, testSubject, testEmail)
				}
			} else {
				if rec.Header().Get("WWW-Authenticate") == "" {
					t.Error("401 without WWW-Authenticate header")
				}
				if gotUserID != "" {
					t.Error("handler ran despite rejection")
				}
			}
		})
	}
}

func TestContextAccessors_Unauthenticated(t *testing.T) {
	ctx := t.Context()
	if UserID(ctx) != "" || Email(ctx) != "" || IdentityFrom(ctx) != nil {
		t.Error("accessors on bare context must return zero values")
	}
}

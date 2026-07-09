package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/api/error_code"
	"github.com/sriganeshlokesh/keysmith/domain/service"
)

// TokenVerifier is what the auth middleware needs from the signer.
// Declared here, at the consumer; satisfied implicitly by *service.Signer.
type TokenVerifier interface {
	VerifyAccessToken(token, issuer, audience string) (*service.AccessClaims, error)
}

type claimsCtxKey struct{}

// RequireAuth rejects requests without a valid Bearer access token and puts
// the verified claims into the request context for handlers (see Claims).
func RequireAuth(verifier TokenVerifier, issuer, audience string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || raw == "" {
				writeUnauthenticated(w)
				return
			}
			claims, err := verifier.VerifyAccessToken(raw, issuer, audience)
			if err != nil {
				writeUnauthenticated(w)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsCtxKey{}, claims)))
		})
	}
}

// Claims returns the access-token claims stored by RequireAuth, or nil when
// the request did not pass through it.
func Claims(ctx context.Context) *service.AccessClaims {
	claims, _ := ctx.Value(claimsCtxKey{}).(*service.AccessClaims)
	return claims
}

func writeUnauthenticated(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(error_code.ErrUnauthenticated.HTTP)
	_ = json.NewEncoder(w).Encode(dto.ErrorResponse{
		Code:    error_code.ErrUnauthenticated.Code,
		Message: error_code.ErrUnauthenticated.Msg,
	})
}

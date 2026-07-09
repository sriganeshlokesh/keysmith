package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/httprate"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/api/error_code"
)

// RateLimitPerIP limits each client IP to rpm requests per minute using a
// sliding-window counter. It must run after chi's RealIP middleware so the
// key is the real client IP behind Railway's edge proxy. rpm <= 0 disables
// limiting entirely.
func RateLimitPerIP(rpm int) func(http.Handler) http.Handler {
	if rpm <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return httprate.LimitBy(
		rpm,
		time.Minute,
		// Key on RemoteAddr: chi's RealIP middleware runs earlier in the
		// stack and rewrites it to the trusted client IP from Railway's
		// X-Forwarded-For, so this is the real caller, not the proxy.
		func(r *http.Request) (string, error) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			return httprate.CanonicalizeIP(ip), nil
		},
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(error_code.ErrRateLimited.HTTP)
			_ = json.NewEncoder(w).Encode(dto.ErrorResponse{
				Code:    error_code.ErrRateLimited.Code,
				Message: error_code.ErrRateLimited.Msg,
			})
		}),
	)
}

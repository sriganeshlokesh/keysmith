package http

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/sriganeshlokesh/keysmith/api/http/middleware"
	"github.com/sriganeshlokesh/keysmith/application/token"
	"github.com/sriganeshlokesh/keysmith/config"
)

// HealthRoutes is what the router needs from the health handler.
// Declared here, at the consumer; satisfied implicitly by *handle.HealthHandler.
type HealthRoutes interface {
	Health(w http.ResponseWriter, r *http.Request)
}

// JWKSRoutes is what the router needs from the JWKS handler.
// Satisfied implicitly by *handle.JWKSHandler.
type JWKSRoutes interface {
	JWKS(w http.ResponseWriter, r *http.Request)
}

// PasswordRoutes is what the router needs from the password handler.
// Satisfied implicitly by *handle.PasswordHandler.
type PasswordRoutes interface {
	Signup(w http.ResponseWriter, r *http.Request)
	Login(w http.ResponseWriter, r *http.Request)
	VerifyEmail(w http.ResponseWriter, r *http.Request)
	RequestPasswordReset(w http.ResponseWriter, r *http.Request)
	ResetPassword(w http.ResponseWriter, r *http.Request)
}

// SessionRoutes is what the router needs from the session handler.
// Satisfied implicitly by *handle.SessionHandler.
type SessionRoutes interface {
	Refresh(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
}

// MeRoutes is what the router needs from the me handler.
// Satisfied implicitly by *handle.MeHandler.
type MeRoutes interface {
	Me(w http.ResponseWriter, r *http.Request)
}

// OAuthRoutes is what the router needs from the OAuth handler.
// Satisfied implicitly by *handle.OAuthHandler.
type OAuthRoutes interface {
	Login(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
}

// Per-IP rate limits from the master plan (Phase 3): 10/min login,
// 3/min signup & reset flows.
const (
	loginRPM  = 10
	signupRPM = 3
	resetRPM  = 3
	verifyRPM = 10
)

// NewRouter constructs a chi router with the standard middleware stack and all routes registered.
// Middleware order: RequestID → RealIP → RequestLogger → Recoverer.
// RequestLogger is placed before Recoverer so that panics are logged as 500s with full duration.
// Auth routes (/auth/*, /.well-known/jwks.json) are registered here as later phases land.
func NewRouter(
	cfg *config.Config,
	logger *slog.Logger,
	health HealthRoutes,
	jwks JWKSRoutes,
	pw PasswordRoutes,
	sessions SessionRoutes,
	me MeRoutes,
	oauthH OAuthRoutes,
	verifier middleware.TokenVerifier,
) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP) //nolint:staticcheck // trusted behind Railway's edge proxy, which always sets X-Forwarded-For
	r.Use(middleware.RequestLogger(logger))
	r.Use(chimw.Recoverer)

	// /healthz stays outside the rate limiters — Railway healthchecks must never 429.
	r.Get("/healthz", health.Health)
	r.Get("/.well-known/jwks.json", jwks.JWKS)

	r.Route("/auth", func(r chi.Router) {
		r.With(middleware.RateLimitPerIP(signupRPM)).Post("/signup", pw.Signup)
		r.With(middleware.RateLimitPerIP(loginRPM)).Post("/login", pw.Login)
		r.With(middleware.RateLimitPerIP(verifyRPM)).Post("/verify-email", pw.VerifyEmail)
		r.With(middleware.RateLimitPerIP(resetRPM)).Post("/request-password-reset", pw.RequestPasswordReset)
		r.With(middleware.RateLimitPerIP(resetRPM)).Post("/reset-password", pw.ResetPassword)

		// Refresh/logout authenticate via the refresh cookie itself.
		r.Post("/refresh", sessions.Refresh)
		r.Post("/logout", sessions.Logout)

		// OIDC: {provider} ∈ google, linkedin (master plan §6).
		r.With(middleware.RateLimitPerIP(loginRPM)).Get("/{provider}/login", oauthH.Login)
		r.Get("/{provider}/callback", oauthH.Callback)

		r.With(middleware.RequireAuth(verifier, cfg.PublicBaseURL, token.Audience)).
			Get("/me", me.Me)
	})

	return r
}

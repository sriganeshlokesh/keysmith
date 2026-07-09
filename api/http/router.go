package http

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/sriganeshlokesh/keysmith/api/http/middleware"
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

// NewRouter constructs a chi router with the standard middleware stack and all routes registered.
// Middleware order: RequestID → RealIP → RequestLogger → Recoverer.
// RequestLogger is placed before Recoverer so that panics are logged as 500s with full duration.
// Auth routes (/auth/*, /.well-known/jwks.json) are registered here as later phases land.
func NewRouter(cfg *config.Config, logger *slog.Logger, health HealthRoutes, jwks JWKSRoutes) http.Handler {
	_ = cfg // used from Phase 3 on (rate limits, CORS)

	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP) //nolint:staticcheck // trusted behind Railway's edge proxy, which always sets X-Forwarded-For
	r.Use(middleware.RequestLogger(logger))
	r.Use(chimw.Recoverer)

	// /healthz stays outside future rate limiters — Railway healthchecks must never 429.
	r.Get("/healthz", health.Health)
	r.Get("/.well-known/jwks.json", jwks.JWKS)

	return r
}

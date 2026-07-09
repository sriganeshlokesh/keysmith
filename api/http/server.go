package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/sriganeshlokesh/keysmith/config"
)

// NewServer constructs an http.Server from the application config.
// Addr uses ":"+PORT (dual-stack wildcard) — do NOT use "0.0.0.0:PORT";
// Railway healthchecks and private networking use IPv6.
func NewServer(cfg *config.Config, h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
}

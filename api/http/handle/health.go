package handle

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/config"
)

// DBPinger is what the health handler needs from the database pool.
// Declared here, at the consumer; satisfied implicitly by *pgxpool.Pool.
type DBPinger interface {
	Ping(ctx context.Context) error
}

// HealthHandler handles GET /healthz: liveness plus a DB ping (master plan §6).
// Railway healthchecks hit this endpoint, so it must stay fast — the ping is
// bounded at 2 seconds.
type HealthHandler struct {
	db      DBPinger
	service string
	version string
}

// NewHealthHandler constructs a HealthHandler from the application config and DB pool.
func NewHealthHandler(cfg *config.Config, db DBPinger) *HealthHandler {
	return &HealthHandler{
		db:      db,
		service: cfg.ServiceName,
		version: cfg.Version,
	}
}

// Health writes a 200 OK when the database is reachable, 503 otherwise.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	resp := dto.HealthResponse{
		Status:  "ok",
		Service: h.service,
		Version: h.version,
	}
	status := http.StatusOK
	if err := h.db.Ping(ctx); err != nil {
		resp.Status = "unavailable"
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

package handle

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/config"
)

type fakePinger struct {
	err error
}

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestHealth(t *testing.T) {
	cfg := &config.Config{ServiceName: "keysmith", Version: "test"}

	tests := []struct {
		name       string
		pingErr    error
		wantCode   int
		wantStatus string
	}{
		{name: "db reachable", pingErr: nil, wantCode: http.StatusOK, wantStatus: "ok"},
		{name: "db unreachable", pingErr: errors.New("connection refused"), wantCode: http.StatusServiceUnavailable, wantStatus: "unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHealthHandler(cfg, fakePinger{err: tt.pingErr})
			rec := httptest.NewRecorder()
			h.Health(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if rec.Code != tt.wantCode {
				t.Errorf("status code = %d, want %d", rec.Code, tt.wantCode)
			}
			var resp dto.HealthResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", resp.Status, tt.wantStatus)
			}
			if resp.Service != "keysmith" {
				t.Errorf("Service = %q, want keysmith", resp.Service)
			}
		})
	}
}

package handle

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/api/error_code"
	"github.com/sriganeshlokesh/keysmith/config"
)

// maxBodyBytes bounds auth request bodies; the largest legitimate payload is
// a password well under this.
const maxBodyBytes = 64 * 1024

// writeJSON encodes v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an ErrorResponse derived from an error_code.Error.
func writeError(w http.ResponseWriter, e *error_code.Error) {
	writeJSON(w, e.HTTP, dto.ErrorResponse{Code: e.Code, Message: e.Msg})
}

// decodeJSON parses the request body into v, rejecting oversized or
// malformed payloads.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, error_code.ErrInvalidParams)
		return false
	}
	return true
}

// refreshCookieName holds the rotating refresh token (master plan §5).
const refreshCookieName = "keysmith_refresh"

// setRefreshCookie binds the raw refresh token to the /auth path only, so it
// is never sent to other endpoints. Host-only (no Domain attribute); Secure
// everywhere except local http development.
func setRefreshCookie(w http.ResponseWriter, cfg *config.Config, value string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     "/auth",
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   cfg.Env != "local",
		SameSite: http.SameSiteLaxMode,
	})
}

func clearRefreshCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Env != "local",
		SameSite: http.SameSiteLaxMode,
	})
}

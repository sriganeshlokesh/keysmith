package handle

import (
	"context"
	"errors"
	"net/http"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/api/error_code"
	"github.com/sriganeshlokesh/keysmith/application/token"
	"github.com/sriganeshlokesh/keysmith/config"
)

// SessionService is what this handler needs from the token use cases.
// Satisfied implicitly by *token.Service.
type SessionService interface {
	Refresh(ctx context.Context, rawToken string) (*token.Session, error)
	Logout(ctx context.Context, rawToken string) error
}

// SessionHandler serves /auth/refresh and /auth/logout (master plan §6).
type SessionHandler struct {
	svc SessionService
	cfg *config.Config
}

// NewSessionHandler constructs a SessionHandler.
func NewSessionHandler(cfg *config.Config, svc SessionService) *SessionHandler {
	return &SessionHandler{svc: svc, cfg: cfg}
}

// Refresh handles POST /auth/refresh: rotate the cookie token, return a new
// access token. Invalid or reused tokens clear the cookie and 401.
func (h *SessionHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, error_code.ErrUnauthenticated)
		return
	}

	sess, err := h.svc.Refresh(r.Context(), cookie.Value)
	if err != nil {
		if errors.Is(err, token.ErrInvalidRefreshToken) || errors.Is(err, token.ErrRefreshReuse) {
			clearRefreshCookie(w, h.cfg)
			writeError(w, error_code.ErrUnauthenticated)
		} else {
			writeError(w, error_code.ErrInternal)
		}
		return
	}

	setRefreshCookie(w, h.cfg, sess.RefreshToken, sess.RefreshExpiresAt)
	writeJSON(w, http.StatusOK, dto.SessionResponse{
		AccessToken: sess.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   sess.AccessExpiresAt.Unix(),
	})
}

// Logout handles POST /auth/logout: revoke the family and clear the cookie.
// Idempotent — logging out without a session still succeeds.
func (h *SessionHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(refreshCookieName); err == nil && cookie.Value != "" {
		if err := h.svc.Logout(r.Context(), cookie.Value); err != nil {
			writeError(w, error_code.ErrInternal)
			return
		}
	}
	clearRefreshCookie(w, h.cfg)
	writeJSON(w, http.StatusOK, dto.MessageResponse{Message: "logged out"})
}

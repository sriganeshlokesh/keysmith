package handle

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/api/error_code"
	"github.com/sriganeshlokesh/keysmith/api/http/middleware"
	"github.com/sriganeshlokesh/keysmith/domain/model"
)

// UserGetter is what the me handler needs to load the profile.
// Satisfied implicitly by *postgres.UserRepo.
type UserGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
}

// MeHandler serves GET /auth/me behind the RequireAuth middleware.
type MeHandler struct {
	users UserGetter
}

// NewMeHandler constructs a MeHandler.
func NewMeHandler(users UserGetter) *MeHandler {
	return &MeHandler{users: users}
}

// Me returns the authenticated user's profile.
func (h *MeHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.Claims(r.Context())
	if claims == nil {
		writeError(w, error_code.ErrUnauthenticated)
		return
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, error_code.ErrUnauthenticated)
		return
	}
	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		// A valid token for a deleted user — treat as unauthenticated.
		writeError(w, error_code.ErrUnauthenticated)
		return
	}
	writeJSON(w, http.StatusOK, dto.MeResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		AvatarURL:     user.AvatarURL,
	})
}

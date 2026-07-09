package handle

import (
	"context"
	"errors"
	"net/http"

	"github.com/sriganeshlokesh/keysmith/api/dto"
	"github.com/sriganeshlokesh/keysmith/api/error_code"
	"github.com/sriganeshlokesh/keysmith/application/password"
	"github.com/sriganeshlokesh/keysmith/application/token"
	"github.com/sriganeshlokesh/keysmith/config"
	"github.com/sriganeshlokesh/keysmith/domain/model"
)

// PasswordService is what this handler needs from the password use cases.
// Declared here, at the consumer; satisfied implicitly by *password.Service.
type PasswordService interface {
	Signup(ctx context.Context, email, pw string) (*model.User, error)
	Login(ctx context.Context, email, pw string) (*model.User, error)
	VerifyEmail(ctx context.Context, rawToken string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, rawToken, newPassword string) error
}

// SessionIssuer is what this handler needs to start a session after login.
// Satisfied implicitly by *token.Service.
type SessionIssuer interface {
	IssueSession(ctx context.Context, user *model.User) (*token.Session, error)
}

// PasswordHandler serves the email+password endpoints (master plan §6).
type PasswordHandler struct {
	svc      PasswordService
	sessions SessionIssuer
	cfg      *config.Config
}

// NewPasswordHandler constructs a PasswordHandler.
func NewPasswordHandler(cfg *config.Config, svc PasswordService, sessions SessionIssuer) *PasswordHandler {
	return &PasswordHandler{svc: svc, sessions: sessions, cfg: cfg}
}

// Signup handles POST /auth/signup.
func (h *PasswordHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req dto.SignupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, err := h.svc.Signup(r.Context(), req.Email, req.Password); err != nil {
		switch {
		case errors.Is(err, password.ErrInvalidEmail), errors.Is(err, password.ErrPasswordPolicy):
			writeError(w, error_code.New(error_code.ErrInvalidParams.Code, err.Error(), http.StatusBadRequest))
		case errors.Is(err, model.ErrEmailTaken):
			writeError(w, error_code.ErrEmailTaken)
		default:
			writeError(w, error_code.ErrInternal)
		}
		return
	}
	writeJSON(w, http.StatusCreated, dto.MessageResponse{
		Message: "account created — check your email to verify your address",
	})
}

// Login handles POST /auth/login: password check, then a fresh session with
// the refresh cookie and an access token in the body.
func (h *PasswordHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user, err := h.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, password.ErrInvalidCredentials):
			writeError(w, error_code.ErrInvalidCredentials)
		case errors.Is(err, password.ErrEmailNotVerified):
			writeError(w, error_code.ErrEmailNotVerified)
		default:
			writeError(w, error_code.ErrInternal)
		}
		return
	}

	sess, err := h.sessions.IssueSession(r.Context(), user)
	if err != nil {
		writeError(w, error_code.ErrInternal)
		return
	}
	setRefreshCookie(w, h.cfg, sess.RefreshToken, sess.RefreshExpiresAt)
	writeJSON(w, http.StatusOK, dto.SessionResponse{
		AccessToken: sess.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   sess.AccessExpiresAt.Unix(),
	})
}

// VerifyEmail handles POST /auth/verify-email.
func (h *PasswordHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req dto.VerifyEmailRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), req.Token); err != nil {
		if errors.Is(err, password.ErrInvalidToken) {
			writeError(w, error_code.ErrInvalidToken)
		} else {
			writeError(w, error_code.ErrInternal)
		}
		return
	}
	writeJSON(w, http.StatusOK, dto.MessageResponse{Message: "email verified"})
}

// RequestPasswordReset handles POST /auth/request-password-reset.
// It answers 200 with the same body whether or not the account exists.
func (h *PasswordHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req dto.RequestPasswordResetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.RequestPasswordReset(r.Context(), req.Email); err != nil {
		writeError(w, error_code.ErrInternal)
		return
	}
	writeJSON(w, http.StatusOK, dto.MessageResponse{
		Message: "if that account exists, a password reset email is on its way",
	})
}

// ResetPassword handles POST /auth/reset-password.
func (h *PasswordHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req dto.ResetPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, password.ErrPasswordPolicy):
			writeError(w, error_code.New(error_code.ErrInvalidParams.Code, err.Error(), http.StatusBadRequest))
		case errors.Is(err, password.ErrInvalidToken):
			writeError(w, error_code.ErrInvalidToken)
		default:
			writeError(w, error_code.ErrInternal)
		}
		return
	}
	writeJSON(w, http.StatusOK, dto.MessageResponse{Message: "password updated — please log in again"})
}

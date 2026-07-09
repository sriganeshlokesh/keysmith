package dto

// ErrorResponse is the error envelope used by all API error responses.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MessageResponse is a plain acknowledgement body.
type MessageResponse struct {
	Message string `json:"message"`
}

// SignupRequest is the body of POST /auth/signup.
type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest is the body of POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// VerifyEmailRequest is the body of POST /auth/verify-email.
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// RequestPasswordResetRequest is the body of POST /auth/request-password-reset.
type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

// ResetPasswordRequest is the body of POST /auth/reset-password.
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// SessionResponse carries a freshly minted access token; the rotated refresh
// token travels only in the httpOnly cookie, never in the body.
type SessionResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"` // always "Bearer"
	ExpiresAt   int64  `json:"expires_at"` // unix seconds
}

// MeResponse is the profile returned by GET /auth/me.
type MeResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          *string `json:"name"`
	AvatarURL     *string `json:"avatar_url"`
}

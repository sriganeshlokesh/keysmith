package model

import (
	"time"

	"github.com/google/uuid"
)

// TokenPurpose scopes a one-time token to a single flow.
type TokenPurpose string

const (
	PurposeEmailVerify   TokenPurpose = "email_verify"
	PurposePasswordReset TokenPurpose = "password_reset"
)

// OneTimeToken backs email verification and password reset links.
// TokenHash is sha256 of the raw token; the raw value is never stored.
type OneTimeToken struct {
	TokenHash  []byte
	UserID     uuid.UUID
	Purpose    TokenPurpose
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

package model

import (
	"time"

	"github.com/google/uuid"
)

// PasswordCredential stores the argon2id hash for password-based login.
// A user has at most one credential; OAuth-only users have none.
type PasswordCredential struct {
	UserID       uuid.UUID
	PasswordHash string // argon2id encoded string
	UpdatedAt    time.Time
}

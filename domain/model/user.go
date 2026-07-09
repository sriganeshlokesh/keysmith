package model

import (
	"time"

	"github.com/google/uuid"
)

// User is the canonical account record. ID doubles as the JWT `sub` claim and
// the foreign key for all user-owned data in forged (master plan §0).
type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	Name          *string
	AvatarURL     *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

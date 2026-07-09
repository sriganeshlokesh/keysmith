package model

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken is one member of a rotation family (master plan §5).
// TokenHash is sha256 of the raw token; the raw value is never stored.
// A non-nil RevokedAt or ReplacedBy on a presented token signals reuse.
type RefreshToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  []byte
	FamilyID   uuid.UUID
	ExpiresAt  time.Time
	CreatedAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *uuid.UUID
}

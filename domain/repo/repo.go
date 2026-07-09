// Package repo declares the repository ports for keysmith's domain entities.
// Implementations live in adapter/repository/postgres. Implementations must
// return the sentinel errors from domain/model (ErrNotFound, ErrEmailTaken,
// ErrDuplicateIdentity) so upper layers can branch without importing
// persistence packages.
package repo

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

// Users is the port for the users table. Create fills ID, CreatedAt, and
// UpdatedAt on the passed entity.
type Users interface {
	Create(ctx context.Context, user *model.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error
}

// Identities is the port for the identities table. Create fills ID and
// CreatedAt on the passed entity.
type Identities interface {
	Create(ctx context.Context, identity *model.Identity) error
	GetByProvider(ctx context.Context, provider model.Provider, providerUserID string) (*model.Identity, error)
}

// PasswordCredentials is the port for the password_credentials table.
// Upsert creates the credential or replaces the hash if one exists
// (signup and password reset share it).
type PasswordCredentials interface {
	Upsert(ctx context.Context, userID uuid.UUID, passwordHash string) error
	GetByUserID(ctx context.Context, userID uuid.UUID) (*model.PasswordCredential, error)
}

// RefreshTokens is the port for the refresh_tokens table. Create fills ID and
// CreatedAt on the passed entity. Rotation and reuse-detection rules compose
// these primitives in the token service (Phase 2, master plan §5).
type RefreshTokens interface {
	Create(ctx context.Context, token *model.RefreshToken) error
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*model.RefreshToken, error)
	SetReplacedBy(ctx context.Context, id, replacedBy uuid.UUID) error
	// RevokeFamily revokes all unrevoked tokens in a family and returns the count.
	RevokeFamily(ctx context.Context, familyID uuid.UUID) (int64, error)
	// RevokeAllForUser revokes all unrevoked tokens for a user (password reset).
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error)
	// DeleteExpiredBefore removes tokens expired or revoked before the cutoff
	// (nightly cleanup job) and returns the count.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

// OneTimeTokens is the port for the one_time_tokens table. Create fills
// CreatedAt on the passed entity.
type OneTimeTokens interface {
	Create(ctx context.Context, token *model.OneTimeToken) error
	// Consume atomically marks an unconsumed, unexpired token as consumed and
	// returns it; it returns model.ErrNotFound otherwise.
	Consume(ctx context.Context, tokenHash []byte, purpose model.TokenPurpose) (*model.OneTimeToken, error)
	// DeleteExpiredBefore removes consumed tokens and tokens expired before
	// the cutoff (nightly cleanup job) and returns the count.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

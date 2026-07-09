package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// IdentityRepo is the pgx implementation of repo.Identities.
type IdentityRepo struct {
	db *pgxpool.Pool
}

var _ repo.Identities = (*IdentityRepo)(nil)

// NewIdentityRepo constructs an IdentityRepo backed by the given pool.
func NewIdentityRepo(db *pgxpool.Pool) *IdentityRepo {
	return &IdentityRepo{db: db}
}

func (r *IdentityRepo) Create(ctx context.Context, identity *model.Identity) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO identities (user_id, provider, provider_user_id)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at`,
		identity.UserID, identity.Provider, identity.ProviderUserID,
	).Scan(&identity.ID, &identity.CreatedAt)
	if isUniqueViolation(err) {
		return model.ErrDuplicateIdentity
	}
	if err != nil {
		return fmt.Errorf("insert identity: %w", err)
	}
	return nil
}

func (r *IdentityRepo) GetByProvider(ctx context.Context, provider model.Provider, providerUserID string) (*model.Identity, error) {
	var id model.Identity
	err := r.db.QueryRow(ctx,
		`SELECT id, user_id, provider, provider_user_id, created_at
		 FROM identities WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&id.ID, &id.UserID, &id.Provider, &id.ProviderUserID, &id.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan identity: %w", err)
	}
	return &id, nil
}

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// CredentialRepo is the pgx implementation of repo.PasswordCredentials.
type CredentialRepo struct {
	db *pgxpool.Pool
}

var _ repo.PasswordCredentials = (*CredentialRepo)(nil)

// NewCredentialRepo constructs a CredentialRepo backed by the given pool.
func NewCredentialRepo(db *pgxpool.Pool) *CredentialRepo {
	return &CredentialRepo{db: db}
}

func (r *CredentialRepo) Upsert(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO password_credentials (user_id, password_hash)
		 VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE
		 SET password_hash = EXCLUDED.password_hash, updated_at = now()`,
		userID, passwordHash)
	if err != nil {
		return fmt.Errorf("upsert password credential: %w", err)
	}
	return nil
}

func (r *CredentialRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*model.PasswordCredential, error) {
	var c model.PasswordCredential
	err := r.db.QueryRow(ctx,
		`SELECT user_id, password_hash, updated_at
		 FROM password_credentials WHERE user_id = $1`,
		userID,
	).Scan(&c.UserID, &c.PasswordHash, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan password credential: %w", err)
	}
	return &c, nil
}

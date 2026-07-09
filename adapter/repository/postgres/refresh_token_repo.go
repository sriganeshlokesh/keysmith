package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// RefreshTokenRepo is the pgx implementation of repo.RefreshTokens.
type RefreshTokenRepo struct {
	db *pgxpool.Pool
}

var _ repo.RefreshTokens = (*RefreshTokenRepo)(nil)

// NewRefreshTokenRepo constructs a RefreshTokenRepo backed by the given pool.
func NewRefreshTokenRepo(db *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

func (r *RefreshTokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at`,
		token.UserID, token.TokenHash, token.FamilyID, token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepo) GetByTokenHash(ctx context.Context, tokenHash []byte) (*model.RefreshToken, error) {
	var t model.RefreshToken
	err := r.db.QueryRow(ctx,
		`SELECT id, user_id, token_hash, family_id, expires_at, created_at, revoked_at, replaced_by
		 FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.FamilyID, &t.ExpiresAt, &t.CreatedAt, &t.RevokedAt, &t.ReplacedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan refresh token: %w", err)
	}
	return &t, nil
}

func (r *RefreshTokenRepo) SetReplacedBy(ctx context.Context, id, replacedBy uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET replaced_by = $2 WHERE id = $1`,
		id, replacedBy)
	if err != nil {
		return fmt.Errorf("set replaced_by: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}

func (r *RefreshTokenRepo) RevokeFamily(ctx context.Context, familyID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		 WHERE family_id = $1 AND revoked_at IS NULL`,
		familyID)
	if err != nil {
		return 0, fmt.Errorf("revoke family: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID)
	if err != nil {
		return 0, fmt.Errorf("revoke all for user: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *RefreshTokenRepo) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	// replaced_by is a self-referencing FK, so clear pointers into the doomed
	// rows first; the referencing rows are themselves old enough to qualify.
	tag, err := r.db.Exec(ctx,
		`WITH doomed AS (
		   SELECT id FROM refresh_tokens
		   WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1)
		 ),
		 unlinked AS (
		   UPDATE refresh_tokens SET replaced_by = NULL
		   WHERE replaced_by IN (SELECT id FROM doomed)
		   RETURNING 1
		 )
		 DELETE FROM refresh_tokens WHERE id IN (SELECT id FROM doomed)`,
		cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// OneTimeTokenRepo is the pgx implementation of repo.OneTimeTokens.
type OneTimeTokenRepo struct {
	db *pgxpool.Pool
}

var _ repo.OneTimeTokens = (*OneTimeTokenRepo)(nil)

// NewOneTimeTokenRepo constructs a OneTimeTokenRepo backed by the given pool.
func NewOneTimeTokenRepo(db *pgxpool.Pool) *OneTimeTokenRepo {
	return &OneTimeTokenRepo{db: db}
}

func (r *OneTimeTokenRepo) Create(ctx context.Context, token *model.OneTimeToken) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO one_time_tokens (token_hash, user_id, purpose, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING created_at`,
		token.TokenHash, token.UserID, token.Purpose, token.ExpiresAt,
	).Scan(&token.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert one-time token: %w", err)
	}
	return nil
}

func (r *OneTimeTokenRepo) Consume(ctx context.Context, tokenHash []byte, purpose model.TokenPurpose) (*model.OneTimeToken, error) {
	var t model.OneTimeToken
	err := r.db.QueryRow(ctx,
		`UPDATE one_time_tokens SET consumed_at = now()
		 WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
		 RETURNING token_hash, user_id, purpose, expires_at, created_at, consumed_at`,
		tokenHash, purpose,
	).Scan(&t.TokenHash, &t.UserID, &t.Purpose, &t.ExpiresAt, &t.CreatedAt, &t.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume one-time token: %w", err)
	}
	return &t, nil
}

func (r *OneTimeTokenRepo) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM one_time_tokens WHERE expires_at < $1 OR consumed_at IS NOT NULL`,
		cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired one-time tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

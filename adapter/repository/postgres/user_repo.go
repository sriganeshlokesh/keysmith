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

// UserRepo is the pgx implementation of repo.Users.
type UserRepo struct {
	db *pgxpool.Pool
}

var _ repo.Users = (*UserRepo)(nil)

// NewUserRepo constructs a UserRepo backed by the given pool.
func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

const userColumns = `id, email, email_verified, name, avatar_url, created_at, updated_at`

func (r *UserRepo) Create(ctx context.Context, user *model.User) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO users (email, email_verified, name, avatar_url)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at, updated_at`,
		user.Email, user.EmailVerified, user.Name, user.AvatarURL,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if isUniqueViolation(err) {
		return model.ErrEmailTaken
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	return scanUser(r.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	return scanUser(r.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1`, email))
}

func (r *UserRepo) SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE users SET email_verified = $2, updated_at = now() WHERE id = $1`,
		id, verified)
	if err != nil {
		return fmt.Errorf("update email_verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}

func scanUser(row pgx.Row) (*model.User, error) {
	var u model.User
	err := row.Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

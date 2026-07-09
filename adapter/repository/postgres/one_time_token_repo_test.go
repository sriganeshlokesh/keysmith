package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

func TestOneTimeTokenRepo_CreateAndConsume(t *testing.T) {
	pool := getTestPool(t)
	repo := NewOneTimeTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "ott@example.com")
	tok := &model.OneTimeToken{
		TokenHash: []byte("verify-hash-1"),
		UserID:    u.ID,
		Purpose:   model.PurposeEmailVerify,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if tok.CreatedAt.IsZero() {
		t.Error("Create() did not fill CreatedAt")
	}

	got, err := repo.Consume(ctx, tok.TokenHash, model.PurposeEmailVerify)
	if err != nil {
		t.Fatalf("Consume() error: %v", err)
	}
	if got.UserID != u.ID || got.ConsumedAt == nil {
		t.Errorf("Consume() = %+v, want user %v with ConsumedAt set", got, u.ID)
	}

	// A token is single-use.
	if _, err := repo.Consume(ctx, tok.TokenHash, model.PurposeEmailVerify); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Consume() second call error = %v, want ErrNotFound", err)
	}
}

func TestOneTimeTokenRepo_ConsumeWrongPurpose(t *testing.T) {
	pool := getTestPool(t)
	repo := NewOneTimeTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "purpose@example.com")
	tok := &model.OneTimeToken{
		TokenHash: []byte("reset-hash-1"),
		UserID:    u.ID,
		Purpose:   model.PurposePasswordReset,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// A reset token must not verify an email.
	if _, err := repo.Consume(ctx, tok.TokenHash, model.PurposeEmailVerify); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Consume() wrong purpose error = %v, want ErrNotFound", err)
	}
	// Still consumable for its real purpose.
	if _, err := repo.Consume(ctx, tok.TokenHash, model.PurposePasswordReset); err != nil {
		t.Errorf("Consume() correct purpose error: %v", err)
	}
}

func TestOneTimeTokenRepo_ConsumeExpired(t *testing.T) {
	pool := getTestPool(t)
	repo := NewOneTimeTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "expired@example.com")
	tok := &model.OneTimeToken{
		TokenHash: []byte("expired-hash"),
		UserID:    u.ID,
		Purpose:   model.PurposeEmailVerify,
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if _, err := repo.Consume(ctx, tok.TokenHash, model.PurposeEmailVerify); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Consume() expired token error = %v, want ErrNotFound", err)
	}
}

func TestOneTimeTokenRepo_DeleteExpiredBefore(t *testing.T) {
	pool := getTestPool(t)
	repo := NewOneTimeTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "ott-cleanup@example.com")
	mk := func(hash string, expiresAt time.Time) *model.OneTimeToken {
		tok := &model.OneTimeToken{TokenHash: []byte(hash), UserID: u.ID, Purpose: model.PurposeEmailVerify, ExpiresAt: expiresAt}
		if err := repo.Create(ctx, tok); err != nil {
			t.Fatalf("Create(%s) error: %v", hash, err)
		}
		return tok
	}
	mk("gone-expired", time.Now().Add(-time.Hour))
	consumed := mk("gone-consumed", time.Now().Add(time.Hour))
	if _, err := repo.Consume(ctx, consumed.TokenHash, model.PurposeEmailVerify); err != nil {
		t.Fatalf("Consume() error: %v", err)
	}
	mk("keep-valid", time.Now().Add(time.Hour))

	n, err := repo.DeleteExpiredBefore(ctx, time.Now())
	if err != nil {
		t.Fatalf("DeleteExpiredBefore() error: %v", err)
	}
	if n != 2 {
		t.Errorf("DeleteExpiredBefore() deleted %d tokens, want 2", n)
	}

	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM one_time_tokens`).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining tokens = %d, want 1", remaining)
	}
}

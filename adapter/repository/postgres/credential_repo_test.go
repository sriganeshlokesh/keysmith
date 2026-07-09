package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

func TestCredentialRepo_UpsertAndGet(t *testing.T) {
	pool := getTestPool(t)
	repo := NewCredentialRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "pw@example.com")
	if err := repo.Upsert(ctx, u.ID, "$argon2id$v=19$hash-one"); err != nil {
		t.Fatalf("Upsert() insert error: %v", err)
	}

	got, err := repo.GetByUserID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByUserID() error: %v", err)
	}
	if got.PasswordHash != "$argon2id$v=19$hash-one" {
		t.Errorf("PasswordHash = %q, want hash-one", got.PasswordHash)
	}
	firstUpdated := got.UpdatedAt

	// Upsert again replaces the hash (password reset path) and bumps updated_at.
	if err := repo.Upsert(ctx, u.ID, "$argon2id$v=19$hash-two"); err != nil {
		t.Fatalf("Upsert() update error: %v", err)
	}
	got, err = repo.GetByUserID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByUserID() error: %v", err)
	}
	if got.PasswordHash != "$argon2id$v=19$hash-two" {
		t.Errorf("PasswordHash = %q, want hash-two", got.PasswordHash)
	}
	if !got.UpdatedAt.After(firstUpdated) {
		t.Error("UpdatedAt not bumped by second Upsert")
	}
}

func TestCredentialRepo_NotFoundAndFK(t *testing.T) {
	pool := getTestPool(t)
	repo := NewCredentialRepo(pool)
	ctx := context.Background()

	if _, err := repo.GetByUserID(ctx, uuid.New()); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByUserID() unknown user error = %v, want ErrNotFound", err)
	}
	if err := repo.Upsert(ctx, uuid.New(), "hash"); err == nil {
		t.Error("Upsert() for nonexistent user succeeded, want FK violation error")
	}
}

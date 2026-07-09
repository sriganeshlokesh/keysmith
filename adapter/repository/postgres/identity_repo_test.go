package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

func TestIdentityRepo_CreateAndGet(t *testing.T) {
	pool := getTestPool(t)
	repo := NewIdentityRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "oauth@example.com")
	id := &model.Identity{UserID: u.ID, Provider: model.ProviderGoogle, ProviderUserID: "google-sub-123"}
	if err := repo.Create(ctx, id); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if id.ID == uuid.Nil || id.CreatedAt.IsZero() {
		t.Error("Create() did not fill ID/CreatedAt")
	}

	got, err := repo.GetByProvider(ctx, model.ProviderGoogle, "google-sub-123")
	if err != nil {
		t.Fatalf("GetByProvider() error: %v", err)
	}
	if got.UserID != u.ID || got.Provider != model.ProviderGoogle {
		t.Errorf("GetByProvider() = %+v, want user %v", got, u.ID)
	}

	// Same subject under a different provider is a distinct identity.
	if _, err := repo.GetByProvider(ctx, model.ProviderLinkedIn, "google-sub-123"); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByProvider() other provider error = %v, want ErrNotFound", err)
	}
}

func TestIdentityRepo_Duplicate(t *testing.T) {
	pool := getTestPool(t)
	repo := NewIdentityRepo(pool)
	ctx := context.Background()

	u1 := createTestUser(t, pool, "one@example.com")
	u2 := createTestUser(t, pool, "two@example.com")

	if err := repo.Create(ctx, &model.Identity{UserID: u1.ID, Provider: model.ProviderLinkedIn, ProviderUserID: "li-1"}); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	err := repo.Create(ctx, &model.Identity{UserID: u2.ID, Provider: model.ProviderLinkedIn, ProviderUserID: "li-1"})
	if !errors.Is(err, model.ErrDuplicateIdentity) {
		t.Errorf("Create() duplicate error = %v, want ErrDuplicateIdentity", err)
	}
}

func TestIdentityRepo_CascadeOnUserDelete(t *testing.T) {
	pool := getTestPool(t)
	repo := NewIdentityRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "cascade@example.com")
	if err := repo.Create(ctx, &model.Identity{UserID: u.ID, Provider: model.ProviderGoogle, ProviderUserID: "g-cascade"}); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, err := repo.GetByProvider(ctx, model.ProviderGoogle, "g-cascade"); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByProvider() after user delete error = %v, want ErrNotFound (ON DELETE CASCADE)", err)
	}
}

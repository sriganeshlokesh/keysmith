package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

func TestUserRepo_CreateAndGet(t *testing.T) {
	pool := getTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	name := "Sri"
	avatar := "https://example.com/a.png"
	u := &model.User{Email: "Sri@Example.com", EmailVerified: true, Name: &name, AvatarURL: &avatar}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if u.ID == uuid.Nil {
		t.Error("Create() did not fill ID")
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Error("Create() did not fill timestamps")
	}

	got, err := repo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID() error: %v", err)
	}
	if got.Email != u.Email || !got.EmailVerified || got.Name == nil || *got.Name != name {
		t.Errorf("GetByID() = %+v, want %+v", got, u)
	}

	// citext: lookup must be case-insensitive.
	got, err = repo.GetByEmail(ctx, "sri@example.COM")
	if err != nil {
		t.Fatalf("GetByEmail() case-insensitive lookup error: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("GetByEmail() ID = %v, want %v", got.ID, u.ID)
	}
}

func TestUserRepo_NullableFields(t *testing.T) {
	pool := getTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "bare@example.com")
	got, err := repo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID() error: %v", err)
	}
	if got.Name != nil || got.AvatarURL != nil {
		t.Errorf("Name = %v, AvatarURL = %v, want both nil", got.Name, got.AvatarURL)
	}
	if got.EmailVerified {
		t.Error("EmailVerified = true, want default false")
	}
}

func TestUserRepo_DuplicateEmail(t *testing.T) {
	pool := getTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	createTestUser(t, pool, "dup@example.com")
	// citext: differing case is still a duplicate.
	err := repo.Create(ctx, &model.User{Email: "DUP@example.com"})
	if !errors.Is(err, model.ErrEmailTaken) {
		t.Errorf("Create() duplicate error = %v, want ErrEmailTaken", err)
	}
}

func TestUserRepo_SetEmailVerified(t *testing.T) {
	pool := getTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "verify@example.com")
	if err := repo.SetEmailVerified(ctx, u.ID, true); err != nil {
		t.Fatalf("SetEmailVerified() error: %v", err)
	}
	got, err := repo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID() error: %v", err)
	}
	if !got.EmailVerified {
		t.Error("EmailVerified = false after SetEmailVerified(true)")
	}
	if !got.UpdatedAt.After(u.UpdatedAt) {
		t.Error("UpdatedAt not bumped by SetEmailVerified")
	}

	if err := repo.SetEmailVerified(ctx, uuid.New(), true); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("SetEmailVerified() unknown id error = %v, want ErrNotFound", err)
	}
}

func TestUserRepo_NotFound(t *testing.T) {
	pool := getTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	if _, err := repo.GetByID(ctx, uuid.New()); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByID() unknown id error = %v, want ErrNotFound", err)
	}
	if _, err := repo.GetByEmail(ctx, "ghost@example.com"); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByEmail() unknown email error = %v, want ErrNotFound", err)
	}
}

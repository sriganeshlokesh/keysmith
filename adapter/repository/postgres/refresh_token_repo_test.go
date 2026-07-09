package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/domain/model"
)

func newRefreshToken(t *testing.T, pool *pgxpool.Pool, userID, familyID uuid.UUID, expiresAt time.Time) *model.RefreshToken {
	t.Helper()
	tok := &model.RefreshToken{
		UserID:    userID,
		TokenHash: []byte(uuid.NewString()), // unique stand-in for sha256(raw)
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
	}
	if err := NewRefreshTokenRepo(pool).Create(context.Background(), tok); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	return tok
}

func TestRefreshTokenRepo_CreateAndGet(t *testing.T) {
	pool := getTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "rt@example.com")
	tok := newRefreshToken(t, pool, u.ID, uuid.New(), time.Now().Add(30*24*time.Hour))
	if tok.ID == uuid.Nil || tok.CreatedAt.IsZero() {
		t.Error("Create() did not fill ID/CreatedAt")
	}

	got, err := repo.GetByTokenHash(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error: %v", err)
	}
	if got.ID != tok.ID || got.UserID != u.ID || got.FamilyID != tok.FamilyID {
		t.Errorf("GetByTokenHash() = %+v, want %+v", got, tok)
	}
	if got.RevokedAt != nil || got.ReplacedBy != nil {
		t.Errorf("fresh token has RevokedAt=%v ReplacedBy=%v, want both nil", got.RevokedAt, got.ReplacedBy)
	}

	if _, err := repo.GetByTokenHash(ctx, []byte("no-such-hash")); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByTokenHash() unknown hash error = %v, want ErrNotFound", err)
	}
}

func TestRefreshTokenRepo_SetReplacedBy(t *testing.T) {
	pool := getTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "rotate@example.com")
	family := uuid.New()
	old := newRefreshToken(t, pool, u.ID, family, time.Now().Add(time.Hour))
	next := newRefreshToken(t, pool, u.ID, family, time.Now().Add(time.Hour))

	if err := repo.SetReplacedBy(ctx, old.ID, next.ID); err != nil {
		t.Fatalf("SetReplacedBy() error: %v", err)
	}
	got, err := repo.GetByTokenHash(ctx, old.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error: %v", err)
	}
	if got.ReplacedBy == nil || *got.ReplacedBy != next.ID {
		t.Errorf("ReplacedBy = %v, want %v", got.ReplacedBy, next.ID)
	}

	if err := repo.SetReplacedBy(ctx, uuid.New(), next.ID); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("SetReplacedBy() unknown id error = %v, want ErrNotFound", err)
	}
}

func TestRefreshTokenRepo_RevokeFamily(t *testing.T) {
	pool := getTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "family@example.com")
	family := uuid.New()
	a := newRefreshToken(t, pool, u.ID, family, time.Now().Add(time.Hour))
	newRefreshToken(t, pool, u.ID, family, time.Now().Add(time.Hour))
	other := newRefreshToken(t, pool, u.ID, uuid.New(), time.Now().Add(time.Hour))

	n, err := repo.RevokeFamily(ctx, family)
	if err != nil {
		t.Fatalf("RevokeFamily() error: %v", err)
	}
	if n != 2 {
		t.Errorf("RevokeFamily() revoked %d tokens, want 2", n)
	}

	got, err := repo.GetByTokenHash(ctx, a.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("family member RevokedAt = nil after RevokeFamily")
	}
	gotOther, err := repo.GetByTokenHash(ctx, other.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error: %v", err)
	}
	if gotOther.RevokedAt != nil {
		t.Error("token outside family was revoked")
	}

	// Already-revoked tokens are not revoked again.
	n, err = repo.RevokeFamily(ctx, family)
	if err != nil {
		t.Fatalf("RevokeFamily() second call error: %v", err)
	}
	if n != 0 {
		t.Errorf("RevokeFamily() second call revoked %d tokens, want 0", n)
	}
}

func TestRefreshTokenRepo_RevokeAllForUser(t *testing.T) {
	pool := getTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "reset@example.com")
	bystander := createTestUser(t, pool, "bystander@example.com")
	newRefreshToken(t, pool, u.ID, uuid.New(), time.Now().Add(time.Hour))
	newRefreshToken(t, pool, u.ID, uuid.New(), time.Now().Add(time.Hour))
	keep := newRefreshToken(t, pool, bystander.ID, uuid.New(), time.Now().Add(time.Hour))

	n, err := repo.RevokeAllForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("RevokeAllForUser() error: %v", err)
	}
	if n != 2 {
		t.Errorf("RevokeAllForUser() revoked %d tokens, want 2", n)
	}
	got, err := repo.GetByTokenHash(ctx, keep.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error: %v", err)
	}
	if got.RevokedAt != nil {
		t.Error("other user's token was revoked")
	}
}

func TestRefreshTokenRepo_DeleteExpiredBefore(t *testing.T) {
	pool := getTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	u := createTestUser(t, pool, "cleanup@example.com")
	family := uuid.New()
	expired := newRefreshToken(t, pool, u.ID, family, time.Now().Add(-time.Hour))
	replaced := newRefreshToken(t, pool, u.ID, family, time.Now().Add(-time.Hour))
	valid := newRefreshToken(t, pool, u.ID, family, time.Now().Add(time.Hour))
	// valid points at an expired row via replaced_by; cleanup must not trip the self-FK.
	if err := repo.SetReplacedBy(ctx, replaced.ID, valid.ID); err != nil {
		t.Fatalf("SetReplacedBy() error: %v", err)
	}
	if err := repo.SetReplacedBy(ctx, valid.ID, expired.ID); err != nil {
		t.Fatalf("SetReplacedBy() error: %v", err)
	}

	n, err := repo.DeleteExpiredBefore(ctx, time.Now())
	if err != nil {
		t.Fatalf("DeleteExpiredBefore() error: %v", err)
	}
	if n != 2 {
		t.Errorf("DeleteExpiredBefore() deleted %d tokens, want 2", n)
	}
	if _, err := repo.GetByTokenHash(ctx, expired.TokenHash); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("expired token still present after cleanup: %v", err)
	}
	got, err := repo.GetByTokenHash(ctx, valid.TokenHash)
	if err != nil {
		t.Fatalf("valid token deleted by cleanup: %v", err)
	}
	if got.ReplacedBy != nil {
		t.Error("valid token's dangling replaced_by was not cleared")
	}
}

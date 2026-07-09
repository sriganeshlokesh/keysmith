package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
	"github.com/sriganeshlokesh/keysmith/domain/service"
)

// fakeUsers is an in-memory repo.Users.
type fakeUsers struct {
	byID map[uuid.UUID]*model.User
}

func (f *fakeUsers) Create(_ context.Context, u *model.User) error {
	u.ID = uuid.New()
	f.byID[u.ID] = u
	return nil
}
func (f *fakeUsers) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, model.ErrNotFound
	}
	return u, nil
}
func (f *fakeUsers) GetByEmail(context.Context, string) (*model.User, error) {
	return nil, model.ErrNotFound
}
func (f *fakeUsers) SetEmailVerified(context.Context, uuid.UUID, bool) error { return nil }

// fakeRefreshTokens is an in-memory repo.RefreshTokens.
type fakeRefreshTokens struct {
	rows map[uuid.UUID]*model.RefreshToken
}

func (f *fakeRefreshTokens) Create(_ context.Context, t *model.RefreshToken) error {
	t.ID = uuid.New()
	t.CreatedAt = time.Now()
	cp := *t
	f.rows[t.ID] = &cp
	return nil
}

func (f *fakeRefreshTokens) GetByTokenHash(_ context.Context, hash []byte) (*model.RefreshToken, error) {
	for _, row := range f.rows {
		if string(row.TokenHash) == string(hash) {
			cp := *row
			return &cp, nil
		}
	}
	return nil, model.ErrNotFound
}

func (f *fakeRefreshTokens) SetReplacedBy(_ context.Context, id, replacedBy uuid.UUID) error {
	row, ok := f.rows[id]
	if !ok {
		return model.ErrNotFound
	}
	row.ReplacedBy = &replacedBy
	return nil
}

func (f *fakeRefreshTokens) RevokeFamily(_ context.Context, familyID uuid.UUID) (int64, error) {
	var n int64
	now := time.Now()
	for _, row := range f.rows {
		if row.FamilyID == familyID && row.RevokedAt == nil {
			row.RevokedAt = &now
			n++
		}
	}
	return n, nil
}

func (f *fakeRefreshTokens) RevokeAllForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	now := time.Now()
	for _, row := range f.rows {
		if row.UserID == userID && row.RevokedAt == nil {
			row.RevokedAt = &now
			n++
		}
	}
	return n, nil
}

func (f *fakeRefreshTokens) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	var n int64
	for id, row := range f.rows {
		if row.ExpiresAt.Before(cutoff) || (row.RevokedAt != nil && row.RevokedAt.Before(cutoff)) {
			delete(f.rows, id)
			n++
		}
	}
	return n, nil
}

var _ repo.Users = (*fakeUsers)(nil)
var _ repo.RefreshTokens = (*fakeRefreshTokens)(nil)

type fixture struct {
	svc    *Service
	users  *fakeUsers
	tokens *fakeRefreshTokens
	user   *model.User
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := service.NewSigner([]service.SigningKey{{Kid: "test", PrivateKey: priv}})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	users := &fakeUsers{byID: map[uuid.UUID]*model.User{}}
	tokens := &fakeRefreshTokens{rows: map[uuid.UUID]*model.RefreshToken{}}
	user := &model.User{Email: "sri@example.com"}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := Config{Issuer: "https://auth.test", AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour}
	return &fixture{
		svc:    NewService(signer, users, tokens, cfg, slog.New(slog.DiscardHandler)),
		users:  users,
		tokens: tokens,
		user:   user,
	}
}

func (fx *fixture) rowFor(t *testing.T, rawToken string) *model.RefreshToken {
	t.Helper()
	sum := sha256.Sum256([]byte(rawToken))
	row, err := fx.tokens.GetByTokenHash(context.Background(), sum[:])
	if err != nil {
		t.Fatalf("row for raw token: %v", err)
	}
	return row
}

func TestIssueSession(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	sess, err := fx.svc.IssueSession(ctx, fx.user)
	if err != nil {
		t.Fatalf("IssueSession() error: %v", err)
	}
	if sess.AccessToken == "" || sess.RefreshToken == "" {
		t.Fatal("IssueSession() returned empty tokens")
	}

	row := fx.rowFor(t, sess.RefreshToken)
	if row.UserID != fx.user.ID {
		t.Errorf("stored UserID = %v, want %v", row.UserID, fx.user.ID)
	}
	if row.FamilyID == uuid.Nil {
		t.Error("stored FamilyID is nil")
	}
	if until := time.Until(row.ExpiresAt); until < 719*time.Hour || until > 721*time.Hour {
		t.Errorf("refresh expiry %v away, want ~720h", until)
	}
}

func TestRefresh_RotatesWithinFamily(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	first, err := fx.svc.IssueSession(ctx, fx.user)
	if err != nil {
		t.Fatalf("IssueSession() error: %v", err)
	}
	second, err := fx.svc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("Refresh() did not rotate the refresh token")
	}

	oldRow := fx.rowFor(t, first.RefreshToken)
	newRow := fx.rowFor(t, second.RefreshToken)
	if newRow.FamilyID != oldRow.FamilyID {
		t.Error("rotated token left its family")
	}
	if oldRow.ReplacedBy == nil || *oldRow.ReplacedBy != newRow.ID {
		t.Errorf("old row ReplacedBy = %v, want %v", oldRow.ReplacedBy, newRow.ID)
	}
	if oldRow.RevokedAt != nil {
		t.Error("normal rotation must not revoke the old token")
	}
}

// TestRefresh_ReuseRevokesFamily is the Phase 2 acceptance check:
// presenting a rotated-out token revokes the entire family.
func TestRefresh_ReuseRevokesFamily(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	first, err := fx.svc.IssueSession(ctx, fx.user)
	if err != nil {
		t.Fatalf("IssueSession() error: %v", err)
	}
	second, err := fx.svc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error: %v", err)
	}

	// An attacker (or stale client) replays the first token.
	if _, err := fx.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("Refresh(replayed) error = %v, want ErrRefreshReuse", err)
	}

	// The whole family is dead: the newest token no longer works either.
	if _, err := fx.svc.Refresh(ctx, second.RefreshToken); !errors.Is(err, ErrRefreshReuse) {
		t.Errorf("Refresh(newest after reuse) error = %v, want ErrRefreshReuse", err)
	}
	if row := fx.rowFor(t, second.RefreshToken); row.RevokedAt == nil {
		t.Error("newest family member not revoked after reuse")
	}
}

func TestRefresh_InvalidTokens(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	if _, err := fx.svc.Refresh(ctx, "never-issued"); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("Refresh(unknown) error = %v, want ErrInvalidRefreshToken", err)
	}

	// Expired token: issue, then time-travel past the TTL.
	sess, err := fx.svc.IssueSession(ctx, fx.user)
	if err != nil {
		t.Fatalf("IssueSession() error: %v", err)
	}
	fx.svc.now = func() time.Time { return time.Now().Add(721 * time.Hour) }
	if _, err := fx.svc.Refresh(ctx, sess.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("Refresh(expired) error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestRefresh_DeletedUser(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	sess, err := fx.svc.IssueSession(ctx, fx.user)
	if err != nil {
		t.Fatalf("IssueSession() error: %v", err)
	}
	delete(fx.users.byID, fx.user.ID)
	if _, err := fx.svc.Refresh(ctx, sess.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("Refresh(deleted user) error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestLogout(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	sess, err := fx.svc.IssueSession(ctx, fx.user)
	if err != nil {
		t.Fatalf("IssueSession() error: %v", err)
	}
	if err := fx.svc.Logout(ctx, sess.RefreshToken); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}
	if row := fx.rowFor(t, sess.RefreshToken); row.RevokedAt == nil {
		t.Error("token not revoked by Logout")
	}
	// Idempotent: unknown token is a no-op.
	if err := fx.svc.Logout(ctx, "never-issued"); err != nil {
		t.Errorf("Logout(unknown) error = %v, want nil", err)
	}
}

func TestAccessTokenClaims(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	sess, err := fx.svc.IssueSession(ctx, fx.user)
	if err != nil {
		t.Fatalf("IssueSession() error: %v", err)
	}
	claims, err := fx.svc.signer.VerifyAccessToken(sess.AccessToken, "https://auth.test", Audience)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error: %v", err)
	}
	if claims.Subject != fx.user.ID.String() {
		t.Errorf("sub = %q, want user id %q", claims.Subject, fx.user.ID)
	}
	if claims.Email != fx.user.Email {
		t.Errorf("email = %q, want %q", claims.Email, fx.user.Email)
	}
}

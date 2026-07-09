package token

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// fakeOneTimeTokens is an in-memory repo.OneTimeTokens.
type fakeOneTimeTokens struct {
	rows map[string]*model.OneTimeToken
}

func (f *fakeOneTimeTokens) Create(_ context.Context, t *model.OneTimeToken) error {
	t.CreatedAt = time.Now()
	f.rows[string(t.TokenHash)] = t
	return nil
}

func (f *fakeOneTimeTokens) Consume(context.Context, []byte, model.TokenPurpose) (*model.OneTimeToken, error) {
	return nil, model.ErrNotFound
}

func (f *fakeOneTimeTokens) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	var n int64
	for k, row := range f.rows {
		if row.ExpiresAt.Before(cutoff) || row.ConsumedAt != nil {
			delete(f.rows, k)
			n++
		}
	}
	return n, nil
}

var _ repo.OneTimeTokens = (*fakeOneTimeTokens)(nil)

func TestCleaner_Run(t *testing.T) {
	refresh := &fakeRefreshTokens{rows: map[uuid.UUID]*model.RefreshToken{}}
	oneTime := &fakeOneTimeTokens{rows: map[string]*model.OneTimeToken{}}
	ctx := context.Background()

	now := time.Now()
	userID := uuid.New()

	// Refresh tokens: one expired well past retention (deleted), one recently
	// expired (kept — inside the 30-day forensic window), one live.
	mkRefresh := func(expiresAt time.Time) {
		t.Helper()
		tok := &model.RefreshToken{UserID: userID, TokenHash: []byte(uuid.NewString()), FamilyID: uuid.New(), ExpiresAt: expiresAt}
		if err := refresh.Create(ctx, tok); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}
	}
	mkRefresh(now.Add(-31 * 24 * time.Hour))
	mkRefresh(now.Add(-1 * time.Hour))
	mkRefresh(now.Add(time.Hour))

	// One-time tokens: expired goes, live stays.
	for hash, expiresAt := range map[string]time.Time{"stale": now.Add(-time.Hour), "live": now.Add(time.Hour)} {
		tok := &model.OneTimeToken{TokenHash: []byte(hash), UserID: userID, Purpose: model.PurposeEmailVerify, ExpiresAt: expiresAt}
		if err := oneTime.Create(ctx, tok); err != nil {
			t.Fatalf("create one-time token: %v", err)
		}
	}

	cleaner := NewCleaner(refresh, oneTime, slog.New(slog.DiscardHandler))
	if err := cleaner.Run(ctx); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if got := len(refresh.rows); got != 2 {
		t.Errorf("refresh rows remaining = %d, want 2 (30-day retention)", got)
	}
	if got := len(oneTime.rows); got != 1 {
		t.Errorf("one-time rows remaining = %d, want 1", got)
	}
}

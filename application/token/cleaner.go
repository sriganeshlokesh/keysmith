package token

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// retention keeps expired/revoked refresh tokens around for 30 days before
// deletion, preserving a window for reuse forensics (master plan §4).
const retention = 30 * 24 * time.Hour

// Cleaner deletes stale refresh and one-time tokens; the nightly job in
// adapter/job drives it.
type Cleaner struct {
	refresh repo.RefreshTokens
	oneTime repo.OneTimeTokens
	logger  *slog.Logger
	now     func() time.Time
}

// NewCleaner constructs a Cleaner.
func NewCleaner(refresh repo.RefreshTokens, oneTime repo.OneTimeTokens, logger *slog.Logger) *Cleaner {
	return &Cleaner{refresh: refresh, oneTime: oneTime, logger: logger, now: time.Now}
}

// Run performs one cleanup pass.
func (c *Cleaner) Run(ctx context.Context) error {
	now := c.now()

	nRefresh, err := c.refresh.DeleteExpiredBefore(ctx, now.Add(-retention))
	if err != nil {
		return fmt.Errorf("clean refresh tokens: %w", err)
	}
	// One-time tokens are short-lived and single-use — no forensic value.
	nOneTime, err := c.oneTime.DeleteExpiredBefore(ctx, now)
	if err != nil {
		return fmt.Errorf("clean one-time tokens: %w", err)
	}

	c.logger.Info("token cleanup pass complete",
		slog.Int64("refresh_tokens_deleted", nRefresh),
		slog.Int64("one_time_tokens_deleted", nOneTime),
	)
	return nil
}

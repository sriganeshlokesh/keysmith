// Package job hosts in-process background tasks.
package job

import (
	"context"
	"log/slog"
	"time"
)

// Runner is what the cleanup job needs from the application layer.
// Declared here, at the consumer; satisfied implicitly by *token.Cleaner.
type Runner interface {
	Run(ctx context.Context) error
}

// Cleanup runs the token cleanup nightly (master plan §4): once at startup,
// then every interval until the context is cancelled.
type Cleanup struct {
	runner   Runner
	logger   *slog.Logger
	interval time.Duration
}

// NewCleanup constructs the nightly cleanup job.
func NewCleanup(runner Runner, logger *slog.Logger) *Cleanup {
	return &Cleanup{runner: runner, logger: logger, interval: 24 * time.Hour}
}

// Start launches the job goroutine; it stops when ctx is cancelled.
func (j *Cleanup) Start(ctx context.Context) {
	go func() {
		j.runOnce(ctx)

		ticker := time.NewTicker(j.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				j.runOnce(ctx)
			}
		}
	}()
}

func (j *Cleanup) runOnce(ctx context.Context) {
	if err := j.runner.Run(ctx); err != nil && ctx.Err() == nil {
		j.logger.Error("token cleanup failed", "error", err)
	}
}

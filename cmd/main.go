package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sriganeshlokesh/keysmith/adapter/dependency"
	"github.com/sriganeshlokesh/keysmith/adapter/repository/postgres"
	"github.com/sriganeshlokesh/keysmith/config"
	applog "github.com/sriganeshlokesh/keysmith/util/log"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := applog.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Config guarantees AutoMigrate is only true when ENV=local (plan §3.8).
	if cfg.AutoMigrate {
		logger.Info("applying migrations", slog.String("reason", "AUTO_MIGRATE=true"))
		if err := postgres.Migrate(ctx, cfg.DatabaseURL); err != nil {
			logger.Error("migrations failed", "error", err)
			os.Exit(1)
		}
	}

	app, cleanup, err := dependency.InitializeApp(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to initialize app", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	server := app.Server
	app.CleanupJob.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		logger.Error("server error", "error", err)
		os.Exit(1)
	case <-ctx.Done():
		stop()
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped cleanly")
	// Small grace period to flush logs before the process exits.
	time.Sleep(50 * time.Millisecond)
}

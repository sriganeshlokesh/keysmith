package log

import (
	"log/slog"
	"os"

	"github.com/sriganeshlokesh/keysmith/config"
)

// New creates a JSON slog.Logger configured from cfg, sets it as the default logger,
// and returns it for use in dependency injection.
func New(cfg *config.Config) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level == slog.LevelDebug,
	}
	handler := slog.NewJSONHandler(os.Stdout, opts)

	logger := slog.New(handler).With(
		slog.String("service", cfg.ServiceName),
		slog.String("env", cfg.Env),
	)

	slog.SetDefault(logger)
	return logger
}

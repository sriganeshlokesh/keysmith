package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Version is stamped at build time via -ldflags "-X github.com/sriganeshlokesh/keysmith/config.Version=..."
var Version = "dev"

// Config holds all application configuration loaded from environment variables.
type Config struct {
	ServiceName     string
	Env             string // local | staging | production
	Port            string
	LogLevel        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Version         string

	DatabaseURL string

	// AutoMigrate is only ever true when Env == "local"; staging and
	// production migrations run from a laptop or CI (master plan §3.8).
	AutoMigrate bool
}

// Load reads configuration from environment variables, applying defaults for any unset values.
// It returns an error if any value cannot be parsed.
func Load() (*Config, error) {
	env := getEnv("ENV", "local")
	switch env {
	case "local", "staging", "production":
	default:
		return nil, fmt.Errorf("ENV must be local, staging, or production, got %q", env)
	}

	port := getEnv("PORT", "8080")
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("PORT must be numeric, got %q: %w", port, err)
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	rawAutoMigrate := getEnv("AUTO_MIGRATE", "false")
	autoMigrate, err := strconv.ParseBool(rawAutoMigrate)
	if err != nil {
		return nil, fmt.Errorf("AUTO_MIGRATE must be a boolean, got %q", rawAutoMigrate)
	}

	readTimeout, err := parseDuration("HTTP_READ_TIMEOUT", "10s")
	if err != nil {
		return nil, err
	}
	writeTimeout, err := parseDuration("HTTP_WRITE_TIMEOUT", "30s")
	if err != nil {
		return nil, err
	}
	idleTimeout, err := parseDuration("HTTP_IDLE_TIMEOUT", "120s")
	if err != nil {
		return nil, err
	}
	shutdownTimeout, err := parseDuration("SHUTDOWN_TIMEOUT", "5s")
	if err != nil {
		return nil, err
	}

	return &Config{
		ServiceName:     getEnv("SERVICE_NAME", "keysmith"),
		Env:             env,
		Port:            port,
		LogLevel:        getEnv("LOG_LEVEL", "info"),
		ReadTimeout:     readTimeout,
		WriteTimeout:    writeTimeout,
		IdleTimeout:     idleTimeout,
		ShutdownTimeout: shutdownTimeout,
		Version:         Version,
		DatabaseURL:     databaseURL,
		AutoMigrate:     autoMigrate && env == "local",
	}, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func parseDuration(envKey, defaultVal string) (time.Duration, error) {
	raw := getEnv(envKey, defaultVal)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration, got %q: %w", envKey, raw, err)
	}
	return d, nil
}

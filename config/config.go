package config

import (
	"encoding/json"
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

	// PublicBaseURL is the externally visible base URL of this service; it is
	// the JWT issuer and the OAuth redirect base (master plan §10).
	PublicBaseURL string

	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// SigningKeys is parsed from AUTH_SIGNING_KEYS. The FIRST entry is the
	// active signing key; all entries are served via JWKS (master plan §5).
	SigningKeys []SigningKeyConfig
	// UsingDevSigningKeys is true when the checked-in local dev keypair is in
	// use; callers should log a warning.
	UsingDevSigningKeys bool
}

// SigningKeyConfig is one entry of the AUTH_SIGNING_KEYS JSON array.
// PrivateKeyB64 is the base64 (standard encoding) of either a 32-byte
// Ed25519 seed or a 64-byte Ed25519 private key.
type SigningKeyConfig struct {
	Kid           string `json:"kid"`
	PrivateKeyB64 string `json:"private_key_b64"`
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

	publicBaseURL := getEnv("PUBLIC_BASE_URL", "")
	if publicBaseURL == "" {
		if env != "local" {
			return nil, fmt.Errorf("PUBLIC_BASE_URL is required when ENV=%s", env)
		}
		publicBaseURL = "http://localhost:" + port
	}

	rawKeys := os.Getenv("AUTH_SIGNING_KEYS")
	usingDevKeys := false
	if rawKeys == "" {
		if env != "local" {
			return nil, fmt.Errorf("AUTH_SIGNING_KEYS is required when ENV=%s", env)
		}
		rawKeys = devSigningKeysJSON
		usingDevKeys = true
	}
	var signingKeys []SigningKeyConfig
	if err := json.Unmarshal([]byte(rawKeys), &signingKeys); err != nil {
		return nil, fmt.Errorf("AUTH_SIGNING_KEYS must be a JSON array of {kid, private_key_b64}: %w", err)
	}
	if len(signingKeys) == 0 {
		return nil, fmt.Errorf("AUTH_SIGNING_KEYS must contain at least one key")
	}
	for i, k := range signingKeys {
		if k.Kid == "" || k.PrivateKeyB64 == "" {
			return nil, fmt.Errorf("AUTH_SIGNING_KEYS[%d]: kid and private_key_b64 are both required", i)
		}
	}

	accessTTL, err := parseDuration("ACCESS_TOKEN_TTL", "15m")
	if err != nil {
		return nil, err
	}
	refreshTTL, err := parseDuration("REFRESH_TOKEN_TTL", "720h")
	if err != nil {
		return nil, err
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
		ServiceName:         getEnv("SERVICE_NAME", "keysmith"),
		Env:                 env,
		Port:                port,
		LogLevel:            getEnv("LOG_LEVEL", "info"),
		ReadTimeout:         readTimeout,
		WriteTimeout:        writeTimeout,
		IdleTimeout:         idleTimeout,
		ShutdownTimeout:     shutdownTimeout,
		Version:             Version,
		DatabaseURL:         databaseURL,
		AutoMigrate:         autoMigrate && env == "local",
		PublicBaseURL:       publicBaseURL,
		AccessTokenTTL:      accessTTL,
		RefreshTokenTTL:     refreshTTL,
		SigningKeys:         signingKeys,
		UsingDevSigningKeys: usingDevKeys,
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

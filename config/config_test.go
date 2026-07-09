package config

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	validDB := "postgres://keysmith:keysmith@localhost:5433/keysmith"
	validKeys := `[{"kid":"2026-07","private_key_b64":"c2VjcmV0"}]`

	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name: "defaults",
			env:  map[string]string{"DATABASE_URL": validDB},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Env != "local" {
					t.Errorf("Env = %q, want local", cfg.Env)
				}
				if cfg.Port != "8080" {
					t.Errorf("Port = %q, want 8080", cfg.Port)
				}
				if cfg.ServiceName != "keysmith" {
					t.Errorf("ServiceName = %q, want keysmith", cfg.ServiceName)
				}
				if cfg.AutoMigrate {
					t.Error("AutoMigrate = true, want false")
				}
			},
		},
		{
			name:    "missing DATABASE_URL",
			env:     map[string]string{},
			wantErr: true,
		},
		{
			name:    "invalid ENV",
			env:     map[string]string{"DATABASE_URL": validDB, "ENV": "prod"},
			wantErr: true,
		},
		{
			name:    "non-numeric PORT",
			env:     map[string]string{"DATABASE_URL": validDB, "PORT": "not-a-port"},
			wantErr: true,
		},
		{
			name: "custom PORT",
			env:  map[string]string{"DATABASE_URL": validDB, "PORT": "9090"},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Port != "9090" {
					t.Errorf("Port = %q, want 9090", cfg.Port)
				}
			},
		},
		{
			name: "AUTO_MIGRATE honored in local",
			env:  map[string]string{"DATABASE_URL": validDB, "ENV": "local", "AUTO_MIGRATE": "true"},
			check: func(t *testing.T, cfg *Config) {
				if !cfg.AutoMigrate {
					t.Error("AutoMigrate = false, want true")
				}
			},
		},
		{
			name: "AUTO_MIGRATE ignored in production",
			env: map[string]string{
				"DATABASE_URL": validDB, "ENV": "production", "AUTO_MIGRATE": "true",
				"PUBLIC_BASE_URL":   "https://auth.example.com",
				"AUTH_SIGNING_KEYS": validKeys,
				"SPA_ORIGIN":        "https://app.example.com",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.AutoMigrate {
					t.Error("AutoMigrate = true, want false in production")
				}
			},
		},
		{
			name:    "invalid AUTO_MIGRATE",
			env:     map[string]string{"DATABASE_URL": validDB, "AUTO_MIGRATE": "yes please"},
			wantErr: true,
		},
		{
			name:    "invalid duration",
			env:     map[string]string{"DATABASE_URL": validDB, "HTTP_READ_TIMEOUT": "ten seconds"},
			wantErr: true,
		},
		{
			name: "dev signing keys fallback in local",
			env:  map[string]string{"DATABASE_URL": validDB, "ENV": "local"},
			check: func(t *testing.T, cfg *Config) {
				if !cfg.UsingDevSigningKeys {
					t.Error("UsingDevSigningKeys = false, want true when unset in local")
				}
				if len(cfg.SigningKeys) == 0 {
					t.Error("SigningKeys empty, want dev key")
				}
				if cfg.PublicBaseURL != "http://localhost:8080" {
					t.Errorf("PublicBaseURL = %q, want localhost default", cfg.PublicBaseURL)
				}
				if cfg.AccessTokenTTL != 15*time.Minute || cfg.RefreshTokenTTL != 720*time.Hour {
					t.Errorf("TTLs = %v/%v, want 15m/720h", cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
				}
			},
		},
		{
			name: "explicit signing keys",
			env:  map[string]string{"DATABASE_URL": validDB, "AUTH_SIGNING_KEYS": validKeys},
			check: func(t *testing.T, cfg *Config) {
				if cfg.UsingDevSigningKeys {
					t.Error("UsingDevSigningKeys = true, want false with explicit keys")
				}
				if len(cfg.SigningKeys) != 1 || cfg.SigningKeys[0].Kid != "2026-07" {
					t.Errorf("SigningKeys = %+v, want one key with kid 2026-07", cfg.SigningKeys)
				}
			},
		},
		{
			name: "missing signing keys in production",
			env: map[string]string{
				"DATABASE_URL": validDB, "ENV": "production",
				"PUBLIC_BASE_URL": "https://auth.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing PUBLIC_BASE_URL in production",
			env: map[string]string{
				"DATABASE_URL": validDB, "ENV": "production",
				"AUTH_SIGNING_KEYS": validKeys,
			},
			wantErr: true,
		},
		{
			name: "missing SPA_ORIGIN in production",
			env: map[string]string{
				"DATABASE_URL": validDB, "ENV": "production",
				"PUBLIC_BASE_URL":   "https://auth.example.com",
				"AUTH_SIGNING_KEYS": validKeys,
			},
			wantErr: true,
		},
		{
			name:    "malformed AUTH_SIGNING_KEYS",
			env:     map[string]string{"DATABASE_URL": validDB, "AUTH_SIGNING_KEYS": "not-json"},
			wantErr: true,
		},
		{
			name:    "signing key missing kid",
			env:     map[string]string{"DATABASE_URL": validDB, "AUTH_SIGNING_KEYS": `[{"private_key_b64":"abc"}]`},
			wantErr: true,
		},
		{
			name:    "empty signing key array",
			env:     map[string]string{"DATABASE_URL": validDB, "AUTH_SIGNING_KEYS": `[]`},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range []string{
				"ENV", "PORT", "DATABASE_URL", "AUTO_MIGRATE", "SERVICE_NAME", "LOG_LEVEL",
				"HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "SHUTDOWN_TIMEOUT",
				"PUBLIC_BASE_URL", "AUTH_SIGNING_KEYS", "ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL",
				"SPA_ORIGIN", "RESEND_API_KEY", "EMAIL_FROM", "SMTP_ADDR",
			} {
				t.Setenv(key, tt.env[key])
			}

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Load() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

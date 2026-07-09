package config

import "testing"

func TestLoad(t *testing.T) {
	validDB := "postgres://keysmith:keysmith@localhost:5433/keysmith"

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
			env:  map[string]string{"DATABASE_URL": validDB, "ENV": "production", "AUTO_MIGRATE": "true"},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range []string{
				"ENV", "PORT", "DATABASE_URL", "AUTO_MIGRATE", "SERVICE_NAME", "LOG_LEVEL",
				"HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "SHUTDOWN_TIMEOUT",
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

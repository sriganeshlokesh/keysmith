package postgres

// Integration tests for the pgx repositories. They need a real Postgres and
// are skipped unless TEST_DATABASE_URL is set — locally, run them with
// `make test-integration` (which boots the compose database first).

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/config"
	"github.com/sriganeshlokesh/keysmith/domain/model"
)

var (
	testPoolOnce sync.Once
	testPool     *pgxpool.Pool
	testPoolErr  error
)

// getTestPool returns a migrated pool shared across the package's tests and
// truncates all tables so each test starts from a clean slate.
func getTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; run integration tests with `make test-integration`")
	}

	testPoolOnce.Do(func() {
		ctx := context.Background()
		if err := Migrate(ctx, url); err != nil {
			testPoolErr = err
			return
		}
		pool, _, err := NewPool(ctx, &config.Config{DatabaseURL: url})
		if err != nil {
			testPoolErr = err
			return
		}
		testPool = pool
	})
	if testPoolErr != nil {
		t.Fatalf("test database setup: %v", testPoolErr)
	}

	_, err := testPool.Exec(context.Background(),
		`TRUNCATE users, identities, password_credentials, refresh_tokens, one_time_tokens CASCADE`)
	if err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	return testPool
}

// createTestUser inserts a user and fails the test on error.
func createTestUser(t *testing.T, pool *pgxpool.Pool, email string) *model.User {
	t.Helper()
	u := &model.User{Email: email}
	if err := NewUserRepo(pool).Create(context.Background(), u); err != nil {
		t.Fatalf("create test user %q: %v", email, err)
	}
	return u
}

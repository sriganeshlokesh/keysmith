// Package postgres provides pgx-backed persistence adapters implementing the
// ports declared in domain/repo.
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/sriganeshlokesh/keysmith/config"
)

// NewPool creates a pgx connection pool for the configured DATABASE_URL.
// The returned cleanup function closes the pool.
func NewPool(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, func(), error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	// Railway Postgres has no bundled pooler; keep each service's footprint
	// small so total connections stay under max_connections (plan §3.6).
	poolCfg.MaxConns = 10
	// Teach pgx to encode/decode uuid columns as github.com/google/uuid values.
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create connection pool: %w", err)
	}
	return pool, pool.Close, nil
}

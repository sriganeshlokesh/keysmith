//go:build wireinject
// +build wireinject

// Package dependency is the composition root for the application.
// It is the ONLY adapter package allowed to import api/*.
//
// Workflow: edit wire.go → make wire → commit wire_gen.go.
// Never import this package from application or domain layers.
package dependency

import (
	"context"
	"log/slog"

	"github.com/google/wire"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/adapter/job"
	"github.com/sriganeshlokesh/keysmith/adapter/repository/postgres"
	apihttp "github.com/sriganeshlokesh/keysmith/api/http"
	"github.com/sriganeshlokesh/keysmith/api/http/handle"
	"github.com/sriganeshlokesh/keysmith/application/token"
	"github.com/sriganeshlokesh/keysmith/config"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
	"github.com/sriganeshlokesh/keysmith/domain/service"
)

// AppSet groups the providers needed to build the App.
// Consumer-declared interfaces are bound to their implementations here.
var AppSet = wire.NewSet(
	postgres.NewPool,
	postgres.NewRefreshTokenRepo,
	postgres.NewOneTimeTokenRepo,
	ProvideSigner,
	token.NewCleaner,
	job.NewCleanup,
	handle.NewHealthHandler,
	handle.NewJWKSHandler,
	apihttp.NewRouter,
	apihttp.NewServer,
	NewApp,
	wire.Bind(new(handle.DBPinger), new(*pgxpool.Pool)),
	wire.Bind(new(handle.JWKSProvider), new(*service.Signer)),
	wire.Bind(new(apihttp.HealthRoutes), new(*handle.HealthHandler)),
	wire.Bind(new(apihttp.JWKSRoutes), new(*handle.JWKSHandler)),
	wire.Bind(new(repo.RefreshTokens), new(*postgres.RefreshTokenRepo)),
	wire.Bind(new(repo.OneTimeTokens), new(*postgres.OneTimeTokenRepo)),
	wire.Bind(new(job.Runner), new(*token.Cleaner)),
)

// InitializeApp is the wire injector that builds the complete App.
// The returned cleanup closes the database pool.
// wire.Build is replaced by generated code in wire_gen.go.
func InitializeApp(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*App, func(), error) {
	wire.Build(AppSet)
	return nil, nil, nil
}

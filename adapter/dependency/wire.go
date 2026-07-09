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
	"net/http"

	"github.com/google/wire"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sriganeshlokesh/keysmith/adapter/repository/postgres"
	apihttp "github.com/sriganeshlokesh/keysmith/api/http"
	"github.com/sriganeshlokesh/keysmith/api/http/handle"
	"github.com/sriganeshlokesh/keysmith/config"
)

// ServerSet groups the providers needed to build an *http.Server.
// Consumer-declared interfaces are bound to their implementations here.
var ServerSet = wire.NewSet(
	postgres.NewPool,
	handle.NewHealthHandler,
	apihttp.NewRouter,
	apihttp.NewServer,
	wire.Bind(new(handle.DBPinger), new(*pgxpool.Pool)),
	wire.Bind(new(apihttp.HealthRoutes), new(*handle.HealthHandler)),
)

// InitializeServer is the wire injector that builds the complete *http.Server.
// The returned cleanup closes the database pool.
// wire.Build is replaced by generated code in wire_gen.go.
func InitializeServer(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*http.Server, func(), error) {
	wire.Build(ServerSet)
	return nil, nil, nil
}

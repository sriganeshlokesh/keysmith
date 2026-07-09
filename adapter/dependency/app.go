package dependency

import (
	"net/http"

	"github.com/sriganeshlokesh/keysmith/adapter/job"
)

// App bundles everything main needs to run: the HTTP server and the
// background jobs whose lifecycle main manages.
type App struct {
	Server     *http.Server
	CleanupJob *job.Cleanup
}

// NewApp constructs the App container.
func NewApp(server *http.Server, cleanupJob *job.Cleanup) *App {
	return &App{Server: server, CleanupJob: cleanupJob}
}

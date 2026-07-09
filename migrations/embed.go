// Package migrations embeds the goose SQL migration files so they can be
// applied programmatically (integration tests, AUTO_MIGRATE in local dev).
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS

// Package core defines the foundational contracts for the application layer.
// Every use case must implement the UseCase interface.
package core

import "context"

// Input is implemented by every use-case request object.
// Validate must return a non-nil error if the input is malformed.
type Input interface {
	Validate() error
}

// Output is implemented by every use-case response object.
// GetStatus returns a short string describing the outcome (e.g. "ok", "created").
type Output interface {
	GetStatus() string
}

// UseCase is the standard contract for application layer operations.
// Each feature has exactly one UseCase implementation.
type UseCase interface {
	Execute(ctx context.Context, in Input) (Output, error)
}

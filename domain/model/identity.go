package model

import (
	"time"

	"github.com/google/uuid"
)

// Provider identifies an external OIDC identity provider.
type Provider string

const (
	ProviderGoogle   Provider = "google"
	ProviderLinkedIn Provider = "linkedin"
)

// Identity links a user to one external OIDC identity.
// (Provider, ProviderUserID) is unique across all users.
type Identity struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Provider       Provider
	ProviderUserID string // OIDC 'sub' from the provider
	CreatedAt      time.Time
}

package model

import "errors"

// Sentinel errors returned by repository implementations so upper layers can
// branch without importing persistence packages.
var (
	// ErrNotFound is returned when a lookup matches no row — including
	// one-time tokens that are already consumed or expired.
	ErrNotFound = errors.New("not found")

	// ErrEmailTaken is returned when creating a user with an email that
	// already exists (case-insensitive via citext).
	ErrEmailTaken = errors.New("email already registered")

	// ErrDuplicateIdentity is returned when the (provider, provider_user_id)
	// pair is already linked to a user.
	ErrDuplicateIdentity = errors.New("identity already linked")
)

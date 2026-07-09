// Package authkit provides local, stateless validation of keysmith-issued
// access tokens for consuming services such as forged: an HTTP middleware,
// a gRPC interceptor, and a cached JWKS fetcher.
//
// The implementation lands in Phase 5 of the auth master plan (docs/PLAN.md).
// This module must stay free of dependencies on keysmith service internals.
package authkit

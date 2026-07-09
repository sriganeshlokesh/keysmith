// Package service holds domain services: business rules that need no I/O,
// such as access-token minting/verification and JWKS construction
// (master plan §5). Rules that orchestrate repositories (rotation, reuse
// detection) live in the application layer instead.
package service

// Package authkit provides local, stateless validation of keysmith-issued
// access tokens for consuming services such as forged: an HTTP middleware,
// a gRPC interceptor (subpackage grpcauth), and a cached JWKS fetcher.
//
// This module must stay free of dependencies on keysmith service internals.
package authkit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Keysmith's checked-in LOCAL DEV keypair (public half). Lets consumers run
// offline against tokens minted by a keysmith started with ENV=local:
//
//	authkit.Config{DevKeyB64: authkit.DevPublicKeyB64}
const (
	DevPublicKeyB64 = "YNZ8OJtAvOD3wy4szOG7lWd3HWvJzdvEgq1oVK8CtkE="
	DevKid          = "dev-1"
)

// Audience is keysmith's fixed `aud` claim (master plan §0).
const Audience = "forge"

const (
	defaultMinRefresh = 5 * time.Minute
	acceptableSkew    = 30 * time.Second
)

// Config configures a Verifier.
type Config struct {
	// JWKSURL is keysmith's JWKS endpoint,
	// e.g. https://auth.example.com/.well-known/jwks.json.
	// Ignored when DevKeyB64 is set.
	JWKSURL string

	// Issuer is the expected `iss` claim — keysmith's PUBLIC_BASE_URL.
	Issuer string

	// Audience is the expected `aud` claim; defaults to "forge".
	Audience string

	// DevKeyB64 enables offline dev mode: a static base64 Ed25519 public key
	// (32 bytes) verified with no network access. Use DevPublicKeyB64 for
	// tokens from a local keysmith.
	DevKeyB64 string
	// DevKid is the `kid` the dev key is registered under; defaults to
	// DevKid ("dev-1", keysmith's dev keypair).
	DevKid string

	// MinRefreshInterval rate-limits forced JWKS refreshes triggered by an
	// unknown `kid`; defaults to 5 minutes.
	MinRefreshInterval time.Duration

	// StartupTimeout bounds the initial JWKS fetch in NewVerifier — the
	// underlying cache would otherwise retry an unreachable endpoint forever.
	// Defaults to 10 seconds.
	StartupTimeout time.Duration

	// Logger is optional; defaults to slog.Default().
	Logger *slog.Logger
}

// Verifier validates keysmith access tokens locally: signature via JWKS
// (cached, refreshed on unknown kid at most every MinRefreshInterval),
// issuer, audience, and expiry with 30s leeway.
type Verifier struct {
	issuer   string
	audience string
	logger   *slog.Logger

	// Exactly one of static / cache is set.
	static  jwk.Set
	cache   *jwk.Cache
	jwksURL string

	minRefresh  time.Duration
	mu          sync.Mutex
	lastRefresh time.Time
}

// NewVerifier builds a Verifier. In JWKS mode it registers the endpoint with
// a background-refreshing cache (honoring the endpoint's Cache-Control) and
// performs the initial fetch, so failures surface at startup.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("authkit: Issuer is required")
	}
	v := &Verifier{
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		logger:     cfg.Logger,
		minRefresh: cfg.MinRefreshInterval,
	}
	if v.audience == "" {
		v.audience = Audience
	}
	if v.logger == nil {
		v.logger = slog.Default()
	}
	if v.minRefresh <= 0 {
		v.minRefresh = defaultMinRefresh
	}

	if cfg.DevKeyB64 != "" {
		set, err := staticDevSet(cfg.DevKeyB64, cfg.DevKid)
		if err != nil {
			return nil, err
		}
		v.static = set
		v.logger.Warn("authkit: using static dev key — local development only")
		return v, nil
	}

	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("authkit: JWKSURL is required (or set DevKeyB64 for dev mode)")
	}
	// ctx governs the cache's background refresh lifecycle; keep it alive for
	// the life of the service.
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("authkit: create JWKS cache: %w", err)
	}

	startupTimeout := cfg.StartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = 10 * time.Second
	}
	// Bound the initial fetch: httprc retries an unreachable endpoint
	// indefinitely, and we want misconfiguration to fail startup instead.
	regCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := cache.Register(regCtx, cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("authkit: fetch JWKS from %s: %w", cfg.JWKSURL, err)
	}
	if _, err := cache.Lookup(regCtx, cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("authkit: fetch JWKS from %s: %w", cfg.JWKSURL, err)
	}
	v.cache = cache
	v.jwksURL = cfg.JWKSURL
	v.lastRefresh = time.Now()
	return v, nil
}

// Identity is the authenticated caller extracted from a valid access token.
type Identity struct {
	// UserID is the `sub` claim — users.id in keysmith and the FK for all
	// user-owned data in forged (master plan §0).
	UserID string
	Email  string
}

// Verify validates a raw access token and returns the caller identity.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Identity, error) {
	set, err := v.keySet(ctx)
	if err != nil {
		return nil, err
	}

	tok, err := v.parse(rawToken, set)
	if err != nil && v.cache != nil {
		// Possibly a fresh signing key we haven't seen (rotation): force one
		// rate-limited refresh and retry.
		if refreshed, ok := v.refreshKeySet(ctx); ok {
			tok, err = v.parse(rawToken, refreshed)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: invalid token: %w", err)
	}

	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("authkit: token has no subject")
	}
	var email string
	_ = tok.Get("email", &email) // optional claim by contract, but always minted

	return &Identity{UserID: sub, Email: email}, nil
}

func (v *Verifier) parse(rawToken string, set jwk.Set) (jwt.Token, error) {
	return jwt.Parse([]byte(rawToken),
		jwt.WithKeySet(set),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithAcceptableSkew(acceptableSkew),
	)
}

func (v *Verifier) keySet(ctx context.Context) (jwk.Set, error) {
	if v.static != nil {
		return v.static, nil
	}
	set, err := v.cache.Lookup(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("authkit: JWKS lookup: %w", err)
	}
	return set, nil
}

// refreshKeySet forces a JWKS refetch, at most once per MinRefreshInterval.
func (v *Verifier) refreshKeySet(ctx context.Context) (jwk.Set, bool) {
	v.mu.Lock()
	if time.Since(v.lastRefresh) < v.minRefresh {
		v.mu.Unlock()
		return nil, false
	}
	v.lastRefresh = time.Now()
	v.mu.Unlock()

	set, err := v.cache.Refresh(ctx, v.jwksURL)
	if err != nil {
		v.logger.Warn("authkit: forced JWKS refresh failed", "error", err)
		return nil, false
	}
	v.logger.Info("authkit: refreshed JWKS after unknown kid")
	return set, true
}

func staticDevSet(keyB64, kid string) (jwk.Set, error) {
	raw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("authkit: decode DevKeyB64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("authkit: DevKeyB64 must be a %d-byte Ed25519 public key, got %d bytes",
			ed25519.PublicKeySize, len(raw))
	}
	key, err := jwk.Import(ed25519.PublicKey(raw))
	if err != nil {
		return nil, fmt.Errorf("authkit: import dev key: %w", err)
	}
	if kid == "" {
		kid = DevKid
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("authkit: set dev kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, "EdDSA"); err != nil {
		return nil, fmt.Errorf("authkit: set dev alg: %w", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, fmt.Errorf("authkit: build dev key set: %w", err)
	}
	return set, nil
}

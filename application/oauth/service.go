// Package oauth implements the OIDC login use case: building the provider
// redirect (state + nonce + PKCE) and resolving the callback into a user via
// the account-linking rules (master plan §6).
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/oauth2"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

var (
	ErrUnknownProvider = errors.New("unknown or unconfigured provider")
	ErrStateMismatch   = errors.New("oauth state mismatch")
	// ErrEmailConflict: the provider email is unverified but already belongs
	// to a user — never auto-link on unverified email (linking rule 3).
	ErrEmailConflict = errors.New("email already in use by another account")
	ErrNoEmail       = errors.New("provider did not supply an email address")
)

// ProviderClaims is the normalized identity a provider hands back.
type ProviderClaims struct {
	Subject       string // OIDC 'sub' — stable per provider
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// IdentityProvider is the port implemented by adapter/oidc for each
// configured provider. Declared here, at the consumer.
type IdentityProvider interface {
	Name() model.Provider
	// AuthCodeURL builds the provider redirect carrying state, nonce, and the
	// PKCE challenge derived from verifier.
	AuthCodeURL(state, nonce, pkceVerifier string) string
	// Exchange redeems the code (with the PKCE verifier), verifies the ID
	// token — including the nonce where the provider honors it — and returns
	// the normalized claims.
	Exchange(ctx context.Context, code, nonce, pkceVerifier string) (*ProviderClaims, error)
}

// BeginResult carries everything the handler needs: where to redirect, and
// what to stash in the short-lived state cookie for the callback.
type BeginResult struct {
	RedirectURL  string
	State        string
	Nonce        string
	PKCEVerifier string
}

// CallbackParams pairs the provider's query values with the state-cookie
// values from Begin.
type CallbackParams struct {
	Code          string
	State         string // from the provider's redirect query
	ExpectedState string // from the state cookie
	Nonce         string
	PKCEVerifier  string
}

// Service resolves OIDC logins against the domain ports.
type Service struct {
	providers  map[model.Provider]IdentityProvider
	users      repo.Users
	identities repo.Identities
	logger     *slog.Logger
}

// NewService constructs the OAuth service over the registered providers.
func NewService(providers map[model.Provider]IdentityProvider, users repo.Users, identities repo.Identities, logger *slog.Logger) *Service {
	return &Service{providers: providers, users: users, identities: identities, logger: logger}
}

// Begin generates the per-attempt secrets and the provider redirect URL.
func (s *Service) Begin(provider model.Provider) (*BeginResult, error) {
	p, ok := s.providers[provider]
	if !ok {
		return nil, ErrUnknownProvider
	}
	state, err := randToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randToken()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()

	return &BeginResult{
		RedirectURL:  p.AuthCodeURL(state, nonce, verifier),
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
	}, nil
}

// Callback validates state, exchanges the code, and applies the linking
// rules, returning the resolved user.
func (s *Service) Callback(ctx context.Context, provider model.Provider, params CallbackParams) (*model.User, error) {
	p, ok := s.providers[provider]
	if !ok {
		return nil, ErrUnknownProvider
	}
	if params.State == "" || params.ExpectedState == "" ||
		subtle.ConstantTimeCompare([]byte(params.State), []byte(params.ExpectedState)) != 1 {
		return nil, ErrStateMismatch
	}

	claims, err := p.Exchange(ctx, params.Code, params.Nonce, params.PKCEVerifier)
	if err != nil {
		return nil, fmt.Errorf("exchange with %s: %w", provider, err)
	}
	return s.resolveUser(ctx, provider, claims)
}

// resolveUser applies the linking rules (master plan §6):
//  1. Identity exists → login as that user.
//  2. Provider email verified AND matches an existing user → link, login.
//  3. Provider email unverified → NEW user, never auto-link. A collision
//     with an existing email is rejected (ErrEmailConflict).
//  4. No matching user → create user (verified per provider claim) + identity.
func (s *Service) resolveUser(ctx context.Context, provider model.Provider, claims *ProviderClaims) (*model.User, error) {
	if claims.Subject == "" {
		return nil, fmt.Errorf("provider %s returned an empty subject", provider)
	}

	// Rule 1.
	ident, err := s.identities.GetByProvider(ctx, provider, claims.Subject)
	if err == nil {
		return s.users.GetByID(ctx, ident.UserID)
	}
	if !errors.Is(err, model.ErrNotFound) {
		return nil, fmt.Errorf("look up identity: %w", err)
	}

	if claims.Email == "" {
		return nil, ErrNoEmail
	}

	// Rule 2.
	if claims.EmailVerified {
		existing, err := s.users.GetByEmail(ctx, claims.Email)
		if err == nil {
			user, err := s.linkIdentity(ctx, provider, claims.Subject, existing)
			if err != nil {
				return nil, err
			}
			s.logger.Info("security_event",
				slog.String("type", "oauth_account_linked"),
				slog.String("provider", string(provider)),
				slog.String("user_id", user.ID.String()),
			)
			return user, nil
		}
		if !errors.Is(err, model.ErrNotFound) {
			return nil, fmt.Errorf("look up user by email: %w", err)
		}
	}

	// Rules 3 & 4.
	user := &model.User{
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          nonEmpty(claims.Name),
		AvatarURL:     nonEmpty(claims.Picture),
	}
	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, model.ErrEmailTaken) {
			// Only reachable with an unverified provider email (rule 3).
			return nil, ErrEmailConflict
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return s.linkIdentity(ctx, provider, claims.Subject, user)
}

// linkIdentity creates the identity row; on a concurrent-creation race it
// resolves to whichever user won.
func (s *Service) linkIdentity(ctx context.Context, provider model.Provider, subject string, user *model.User) (*model.User, error) {
	err := s.identities.Create(ctx, &model.Identity{
		UserID:         user.ID,
		Provider:       provider,
		ProviderUserID: subject,
	})
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, model.ErrDuplicateIdentity) {
		return nil, fmt.Errorf("create identity: %w", err)
	}

	// Race: another request linked this identity first — follow it.
	ident, err := s.identities.GetByProvider(ctx, provider, subject)
	if err != nil {
		return nil, fmt.Errorf("re-resolve identity after race: %w", err)
	}
	s.logger.Warn("oauth identity creation raced; following existing link",
		slog.String("provider", string(provider)),
		slog.String("user_id", ident.UserID.String()),
	)
	return s.users.GetByID(ctx, ident.UserID)
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func randToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

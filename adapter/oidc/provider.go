// Package oidc implements the oauth.IdentityProvider port over standard OIDC
// discovery, using coreos/go-oidc and golang.org/x/oauth2 (master plan §2).
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/sriganeshlokesh/keysmith/application/oauth"
	"github.com/sriganeshlokesh/keysmith/domain/model"
)

// Options configures one provider client.
type Options struct {
	Name         model.Provider
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// HonorNonce enforces that the nonce round-trips through the ID token.
	// LinkedIn's OIDC does not reliably return it (master plan §6), so it is
	// disabled there; state + PKCE still bind the flow to this browser.
	HonorNonce bool
	// UsePKCE sends a S256 code challenge with the authorization request.
	UsePKCE bool
}

// Client is a single configured OIDC provider.
type Client struct {
	opts     Options
	oauth    oauth2.Config
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
}

var _ oauth.IdentityProvider = (*Client)(nil)

// New runs OIDC discovery for the issuer and builds the client.
func New(ctx context.Context, opts Options) (*Client, error) {
	provider, err := gooidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s (%s): %w", opts.Name, opts.Issuer, err)
	}
	return &Client{
		opts: opts,
		oauth: oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  opts.RedirectURL,
			Scopes:       opts.Scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&gooidc.Config{ClientID: opts.ClientID}),
	}, nil
}

func (c *Client) Name() model.Provider {
	return c.opts.Name
}

func (c *Client) AuthCodeURL(state, nonce, pkceVerifier string) string {
	authOpts := []oauth2.AuthCodeOption{gooidc.Nonce(nonce)}
	if c.opts.UsePKCE {
		authOpts = append(authOpts, oauth2.S256ChallengeOption(pkceVerifier))
	}
	return c.oauth.AuthCodeURL(state, authOpts...)
}

func (c *Client) Exchange(ctx context.Context, code, nonce, pkceVerifier string) (*oauth.ProviderClaims, error) {
	var exchangeOpts []oauth2.AuthCodeOption
	if c.opts.UsePKCE {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(pkceVerifier))
	}
	token, err := c.oauth.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("token response has no id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if c.opts.HonorNonce && idToken.Nonce != nonce {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}

	var claims struct {
		Email         string   `json:"email"`
		EmailVerified flexBool `json:"email_verified"`
		Name          string   `json:"name"`
		Picture       string   `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse id_token claims: %w", err)
	}

	// Some providers keep ID tokens thin; fall back to the userinfo endpoint
	// when the email claim is missing (master plan §6, LinkedIn quirk).
	if claims.Email == "" {
		userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, fmt.Errorf("userinfo fallback: %w", err)
		}
		if err := userInfo.Claims(&claims); err != nil {
			return nil, fmt.Errorf("parse userinfo claims: %w", err)
		}
	}

	return &oauth.ProviderClaims{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: bool(claims.EmailVerified),
		Name:          claims.Name,
		Picture:       claims.Picture,
	}, nil
}

// flexBool tolerates providers that encode email_verified as a string
// ("true"/"false") instead of a JSON boolean.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case "true":
		*b = true
		return nil
	case "false", "null":
		*b = false
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("email_verified: unsupported value %s", data)
	}
	parsed, err := strconv.ParseBool(s)
	if err != nil {
		return fmt.Errorf("email_verified: unsupported value %q", s)
	}
	*b = flexBool(parsed)
	return nil
}

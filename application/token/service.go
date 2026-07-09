// Package token implements the session-token use cases: issuing sessions,
// refresh rotation with reuse detection, logout, and expired-token cleanup
// (master plan §5).
package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
	"github.com/sriganeshlokesh/keysmith/domain/service"
)

// Sentinel errors; handlers map both to a generic 401.
var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrRefreshReuse means a rotated-out or revoked token was presented —
	// the whole family has been revoked in response.
	ErrRefreshReuse = errors.New("refresh token reuse detected")
)

// Audience is the fixed `aud` claim of every access token (master plan §0).
const Audience = "forge"

// Session is an issued access/refresh token pair. RefreshToken is the raw
// value bound to the httpOnly cookie by the handler; only its hash is stored.
type Session struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// Config carries the token parameters from application config.
type Config struct {
	Issuer     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// Service issues and rotates sessions against the domain ports.
type Service struct {
	signer *service.Signer
	users  repo.Users
	tokens repo.RefreshTokens
	cfg    Config
	logger *slog.Logger
	now    func() time.Time
}

// NewService constructs the token service.
func NewService(signer *service.Signer, users repo.Users, tokens repo.RefreshTokens, cfg Config, logger *slog.Logger) *Service {
	return &Service{signer: signer, users: users, tokens: tokens, cfg: cfg, logger: logger, now: time.Now}
}

// IssueSession starts a new refresh-token family for the user (login/signup/
// OAuth callback) and mints the first access token.
func (s *Service) IssueSession(ctx context.Context, user *model.User) (*Session, error) {
	session, _, err := s.issue(ctx, user, uuid.New())
	return session, err
}

// Refresh rotates the presented refresh token: reuse of a rotated-out or
// revoked token revokes the entire family (master plan §5).
func (s *Service) Refresh(ctx context.Context, rawToken string) (*Session, error) {
	current, err := s.tokens.GetByTokenHash(ctx, hashToken(rawToken))
	if errors.Is(err, model.ErrNotFound) {
		return nil, ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, fmt.Errorf("look up refresh token: %w", err)
	}

	if current.RevokedAt != nil || current.ReplacedBy != nil {
		revoked, revokeErr := s.tokens.RevokeFamily(ctx, current.FamilyID)
		if revokeErr != nil {
			s.logger.Error("failed to revoke family after reuse", "error", revokeErr,
				slog.String("family_id", current.FamilyID.String()))
		}
		s.logger.Warn("security_event",
			slog.String("type", "refresh_token_reuse"),
			slog.String("user_id", current.UserID.String()),
			slog.String("family_id", current.FamilyID.String()),
			slog.Int64("tokens_revoked", revoked),
		)
		return nil, ErrRefreshReuse
	}

	if s.now().After(current.ExpiresAt) {
		return nil, ErrInvalidRefreshToken
	}

	user, err := s.users.GetByID(ctx, current.UserID)
	if errors.Is(err, model.ErrNotFound) {
		return nil, ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, fmt.Errorf("load user for refresh: %w", err)
	}

	session, next, err := s.issue(ctx, user, current.FamilyID)
	if err != nil {
		return nil, err
	}
	if err := s.tokens.SetReplacedBy(ctx, current.ID, next.ID); err != nil {
		return nil, fmt.Errorf("mark token replaced: %w", err)
	}
	return session, nil
}

// Logout revokes the presented token's whole family. Unknown tokens are a
// no-op so logout stays idempotent.
func (s *Service) Logout(ctx context.Context, rawToken string) error {
	current, err := s.tokens.GetByTokenHash(ctx, hashToken(rawToken))
	if errors.Is(err, model.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up refresh token: %w", err)
	}
	if _, err := s.tokens.RevokeFamily(ctx, current.FamilyID); err != nil {
		return fmt.Errorf("revoke family: %w", err)
	}
	return nil
}

func (s *Service) issue(ctx context.Context, user *model.User, familyID uuid.UUID) (*Session, *model.RefreshToken, error) {
	raw, hash, err := newRefreshToken()
	if err != nil {
		return nil, nil, err
	}

	now := s.now()
	rt := &model.RefreshToken{
		UserID:    user.ID,
		TokenHash: hash,
		FamilyID:  familyID,
		ExpiresAt: now.Add(s.cfg.RefreshTTL),
	}
	if err := s.tokens.Create(ctx, rt); err != nil {
		return nil, nil, fmt.Errorf("store refresh token: %w", err)
	}

	access, err := s.signer.MintAccessToken(now, user, s.cfg.Issuer, Audience, s.cfg.AccessTTL)
	if err != nil {
		return nil, nil, err
	}

	return &Session{
		AccessToken:      access,
		AccessExpiresAt:  now.Add(s.cfg.AccessTTL),
		RefreshToken:     raw,
		RefreshExpiresAt: rt.ExpiresAt,
	}, rt, nil
}

// newRefreshToken returns a 256-bit random token (base64url) and the
// sha256 hash under which it is stored (master plan §5).
func newRefreshToken() (string, []byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

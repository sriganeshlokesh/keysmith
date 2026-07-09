// Package password implements the email+password use cases: signup, login,
// email verification, and password reset (master plan §6).
package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"sync"
	"time"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
	"github.com/sriganeshlokesh/keysmith/domain/service"
)

// Sentinel errors mapped to HTTP statuses by the handlers.
var (
	ErrInvalidEmail   = errors.New("invalid email address")
	ErrPasswordPolicy = errors.New("password must be between 8 and 512 characters")
	// ErrInvalidCredentials is deliberately generic: unknown email and wrong
	// password are indistinguishable (no user enumeration, master plan §11).
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

const (
	verifyTokenTTL = 24 * time.Hour
	resetTokenTTL  = time.Hour
)

// EmailSender is the transport this service needs to deliver mail.
// Declared here, at the consumer; adapters live in adapter/email.
type EmailSender interface {
	Send(ctx context.Context, to, subject, html string) error
}

// Config carries the password-flow parameters from application config.
type Config struct {
	// SPAOrigin is the base for verification/reset links in emails.
	SPAOrigin string
}

// Service implements the password-auth flows against the domain ports.
type Service struct {
	users   repo.Users
	creds   repo.PasswordCredentials
	oneTime repo.OneTimeTokens
	refresh repo.RefreshTokens
	email   EmailSender
	cfg     Config
	logger  *slog.Logger
	now     func() time.Time

	// dummyHash equalizes login timing for unknown emails (no enumeration).
	dummyHash string
	// bg tracks async email sends so tests and shutdown can wait for them.
	bg sync.WaitGroup
}

// NewService constructs the password service. It hashes a throwaway value up
// front so failed lookups can burn the same time as real comparisons.
func NewService(
	users repo.Users,
	creds repo.PasswordCredentials,
	oneTime repo.OneTimeTokens,
	refresh repo.RefreshTokens,
	email EmailSender,
	cfg Config,
	logger *slog.Logger,
) (*Service, error) {
	dummy := make([]byte, 32)
	if _, err := rand.Read(dummy); err != nil {
		return nil, fmt.Errorf("generate dummy password: %w", err)
	}
	dummyHash, err := service.HashPassword(base64.StdEncoding.EncodeToString(dummy))
	if err != nil {
		return nil, fmt.Errorf("hash dummy password: %w", err)
	}
	return &Service{
		users: users, creds: creds, oneTime: oneTime, refresh: refresh,
		email: email, cfg: cfg, logger: logger, now: time.Now, dummyHash: dummyHash,
	}, nil
}

// Signup creates a user and credential and sends the verification email.
// The email is best-effort: a delivery failure must not orphan the signup.
func (s *Service) Signup(ctx context.Context, email, password string) (*model.User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := service.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &model.User{Email: email}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err // model.ErrEmailTaken passes through
	}
	if err := s.creds.Upsert(ctx, user.ID, hash); err != nil {
		return nil, fmt.Errorf("store credential: %w", err)
	}

	if err := s.sendVerificationEmail(ctx, user); err != nil {
		s.logger.Error("failed to send verification email", "error", err,
			slog.String("user_id", user.ID.String()))
	}
	return user, nil
}

// Login validates credentials and returns the user. Unknown emails and
// OAuth-only accounts burn a dummy hash comparison so response timing does
// not reveal account existence.
func (s *Service) Login(ctx context.Context, email, password string) (*model.User, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, model.ErrNotFound) {
		s.burnComparison(password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("look up user: %w", err)
	}

	cred, err := s.creds.GetByUserID(ctx, user.ID)
	if errors.Is(err, model.ErrNotFound) {
		s.burnComparison(password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("look up credential: %w", err)
	}

	match, err := service.VerifyPassword(password, cred.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !match {
		return nil, ErrInvalidCredentials
	}
	if !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}
	return user, nil
}

// VerifyEmail consumes a verification token and marks the email verified.
func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	tok, err := s.oneTime.Consume(ctx, hashToken(rawToken), model.PurposeEmailVerify)
	if errors.Is(err, model.ErrNotFound) {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("consume verification token: %w", err)
	}
	if err := s.users.SetEmailVerified(ctx, tok.UserID, true); err != nil {
		return fmt.Errorf("mark email verified: %w", err)
	}
	return nil
}

// RequestPasswordReset always succeeds regardless of account existence
// (master plan §6). For known accounts the token+email work happens in the
// background, keeping the response path identical to the unknown-email one.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, model.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up user: %w", err)
	}

	s.bg.Go(func() {
		bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.sendResetEmail(bgCtx, user); err != nil {
			s.logger.Error("failed to send password reset email", "error", err,
				slog.String("user_id", user.ID.String()))
		}
	})
	return nil
}

// ResetPassword consumes a reset token, replaces the credential, and revokes
// every refresh-token family for the user (master plan §6). Consuming a
// token emailed to the address also proves ownership, so the email is
// marked verified.
func (s *Service) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	tok, err := s.oneTime.Consume(ctx, hashToken(rawToken), model.PurposePasswordReset)
	if errors.Is(err, model.ErrNotFound) {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("consume reset token: %w", err)
	}

	hash, err := service.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := s.creds.Upsert(ctx, tok.UserID, hash); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	if err := s.users.SetEmailVerified(ctx, tok.UserID, true); err != nil {
		return fmt.Errorf("mark email verified: %w", err)
	}

	revoked, err := s.refresh.RevokeAllForUser(ctx, tok.UserID)
	if err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	s.logger.Warn("security_event",
		slog.String("type", "password_reset"),
		slog.String("user_id", tok.UserID.String()),
		slog.Int64("sessions_revoked", revoked),
	)
	return nil
}

// Wait blocks until in-flight background email sends finish (shutdown/tests).
func (s *Service) Wait() {
	s.bg.Wait()
}

func (s *Service) sendVerificationEmail(ctx context.Context, user *model.User) error {
	raw, hashed, err := newRawToken()
	if err != nil {
		return err
	}
	tok := &model.OneTimeToken{
		TokenHash: hashed,
		UserID:    user.ID,
		Purpose:   model.PurposeEmailVerify,
		ExpiresAt: s.now().Add(verifyTokenTTL),
	}
	if err := s.oneTime.Create(ctx, tok); err != nil {
		return fmt.Errorf("store verification token: %w", err)
	}
	subject, html := verificationEmail(s.cfg.SPAOrigin + "/verify-email?token=" + raw)
	return s.email.Send(ctx, user.Email, subject, html)
}

func (s *Service) sendResetEmail(ctx context.Context, user *model.User) error {
	raw, hashed, err := newRawToken()
	if err != nil {
		return err
	}
	tok := &model.OneTimeToken{
		TokenHash: hashed,
		UserID:    user.ID,
		Purpose:   model.PurposePasswordReset,
		ExpiresAt: s.now().Add(resetTokenTTL),
	}
	if err := s.oneTime.Create(ctx, tok); err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}
	subject, html := passwordResetEmail(s.cfg.SPAOrigin + "/reset-password?token=" + raw)
	return s.email.Send(ctx, user.Email, subject, html)
}

// burnComparison spends the same time a real argon2id comparison would, so
// "no such account" and "wrong password" are indistinguishable by timing.
func (s *Service) burnComparison(password string) {
	_, _ = service.VerifyPassword(password, s.dummyHash)
}

func normalizeEmail(email string) (string, error) {
	if len(email) > 255 {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", ErrInvalidEmail
	}
	return addr.Address, nil
}

func validatePassword(password string) error {
	if len(password) < 8 || len(password) > 512 {
		return ErrPasswordPolicy
	}
	return nil
}

// newRawToken returns a 256-bit random token (base64url) and the sha256 hash
// under which it is stored — same shape as refresh tokens (master plan §5).
func newRawToken() (string, []byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

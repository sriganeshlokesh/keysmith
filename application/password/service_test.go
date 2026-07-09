package password

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// ── In-memory fakes ────────────────────────────────────────────────────────────

type fakeUsers struct {
	byID map[uuid.UUID]*model.User
}

func (f *fakeUsers) Create(_ context.Context, u *model.User) error {
	for _, existing := range f.byID {
		if strings.EqualFold(existing.Email, u.Email) {
			return model.ErrEmailTaken
		}
	}
	u.ID = uuid.New()
	f.byID[u.ID] = u
	return nil
}
func (f *fakeUsers) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, model.ErrNotFound
	}
	return u, nil
}
func (f *fakeUsers) GetByEmail(_ context.Context, email string) (*model.User, error) {
	for _, u := range f.byID {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return nil, model.ErrNotFound
}
func (f *fakeUsers) SetEmailVerified(_ context.Context, id uuid.UUID, v bool) error {
	u, ok := f.byID[id]
	if !ok {
		return model.ErrNotFound
	}
	u.EmailVerified = v
	return nil
}

type fakeCreds struct {
	byUser map[uuid.UUID]string
}

func (f *fakeCreds) Upsert(_ context.Context, userID uuid.UUID, hash string) error {
	f.byUser[userID] = hash
	return nil
}
func (f *fakeCreds) GetByUserID(_ context.Context, userID uuid.UUID) (*model.PasswordCredential, error) {
	hash, ok := f.byUser[userID]
	if !ok {
		return nil, model.ErrNotFound
	}
	return &model.PasswordCredential{UserID: userID, PasswordHash: hash}, nil
}

type fakeOneTime struct {
	mu   sync.Mutex
	rows map[string]*model.OneTimeToken
}

func (f *fakeOneTime) Create(_ context.Context, t *model.OneTimeToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t.CreatedAt = time.Now()
	f.rows[string(t.TokenHash)] = t
	return nil
}
func (f *fakeOneTime) Consume(_ context.Context, hash []byte, purpose model.TokenPurpose) (*model.OneTimeToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[string(hash)]
	if !ok || row.Purpose != purpose || row.ConsumedAt != nil || time.Now().After(row.ExpiresAt) {
		return nil, model.ErrNotFound
	}
	now := time.Now()
	row.ConsumedAt = &now
	return row, nil
}
func (f *fakeOneTime) DeleteExpiredBefore(context.Context, time.Time) (int64, error) { return 0, nil }

type fakeRefresh struct {
	revokedUsers []uuid.UUID
}

func (f *fakeRefresh) Create(context.Context, *model.RefreshToken) error { return nil }
func (f *fakeRefresh) GetByTokenHash(context.Context, []byte) (*model.RefreshToken, error) {
	return nil, model.ErrNotFound
}
func (f *fakeRefresh) SetReplacedBy(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (f *fakeRefresh) RevokeFamily(context.Context, uuid.UUID) (int64, error)    { return 0, nil }
func (f *fakeRefresh) RevokeAllForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	f.revokedUsers = append(f.revokedUsers, userID)
	return 2, nil
}
func (f *fakeRefresh) DeleteExpiredBefore(context.Context, time.Time) (int64, error) { return 0, nil }

type sentEmail struct {
	to      string
	subject string
	html    string
}

type fakeEmail struct {
	mu   sync.Mutex
	sent []sentEmail
}

func (f *fakeEmail) Send(_ context.Context, to, subject, html string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentEmail{to: to, subject: subject, html: html})
	return nil
}
func (f *fakeEmail) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}
func (f *fakeEmail) last() sentEmail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[len(f.sent)-1]
}

var (
	_ repo.Users               = (*fakeUsers)(nil)
	_ repo.PasswordCredentials = (*fakeCreds)(nil)
	_ repo.OneTimeTokens       = (*fakeOneTime)(nil)
	_ repo.RefreshTokens       = (*fakeRefresh)(nil)
)

// ── Fixture ────────────────────────────────────────────────────────────────────

type fixture struct {
	svc     *Service
	users   *fakeUsers
	creds   *fakeCreds
	oneTime *fakeOneTime
	refresh *fakeRefresh
	email   *fakeEmail
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fx := &fixture{
		users:   &fakeUsers{byID: map[uuid.UUID]*model.User{}},
		creds:   &fakeCreds{byUser: map[uuid.UUID]string{}},
		oneTime: &fakeOneTime{rows: map[string]*model.OneTimeToken{}},
		refresh: &fakeRefresh{},
		email:   &fakeEmail{},
	}
	svc, err := NewService(fx.users, fx.creds, fx.oneTime, fx.refresh, fx.email,
		Config{SPAOrigin: "http://spa.test"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	fx.svc = svc
	return fx
}

// tokenFromLink extracts the raw one-time token from the last sent email.
func (fx *fixture) tokenFromLink(t *testing.T) string {
	t.Helper()
	html := fx.email.last().html
	_, after, found := strings.Cut(html, "token=")
	if !found {
		t.Fatalf("no token link in email: %q", html)
	}
	end := strings.IndexAny(after, `"<& `)
	if end == -1 {
		t.Fatalf("unterminated token in email: %q", html)
	}
	return after[:end]
}

func (fx *fixture) signup(t *testing.T, email, pw string) *model.User {
	t.Helper()
	u, err := fx.svc.Signup(context.Background(), email, pw)
	if err != nil {
		t.Fatalf("Signup(%s) error: %v", email, err)
	}
	return u
}

// ── Tests ──────────────────────────────────────────────────────────────────────

func TestSignup(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	u := fx.signup(t, "sri@example.com", "hunter2hunter2")
	if u.EmailVerified {
		t.Error("new signup is already verified")
	}
	if fx.email.count() != 1 {
		t.Fatalf("verification emails sent = %d, want 1", fx.email.count())
	}
	if got := fx.email.last().to; got != "sri@example.com" {
		t.Errorf("email to = %q", got)
	}
	if !strings.Contains(fx.email.last().html, "http://spa.test/verify-email?token=") {
		t.Errorf("email missing verify link: %q", fx.email.last().html)
	}
	if _, ok := fx.creds.byUser[u.ID]; !ok {
		t.Error("no credential stored for new user")
	}

	if _, err := fx.svc.Signup(ctx, "sri@example.com", "anotherpassword"); !errors.Is(err, model.ErrEmailTaken) {
		t.Errorf("duplicate Signup() error = %v, want ErrEmailTaken", err)
	}
	if _, err := fx.svc.Signup(ctx, "not-an-email", "hunter2hunter2"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("Signup(bad email) error = %v, want ErrInvalidEmail", err)
	}
	if _, err := fx.svc.Signup(ctx, "ok@example.com", "short"); !errors.Is(err, ErrPasswordPolicy) {
		t.Errorf("Signup(short pw) error = %v, want ErrPasswordPolicy", err)
	}
}

func TestVerifyEmailAndLogin(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	u := fx.signup(t, "sri@example.com", "hunter2hunter2")

	// Unverified login is rejected after a correct password.
	if _, err := fx.svc.Login(ctx, "sri@example.com", "hunter2hunter2"); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("Login(unverified) error = %v, want ErrEmailNotVerified", err)
	}

	tok := fx.tokenFromLink(t)
	if err := fx.svc.VerifyEmail(ctx, tok); err != nil {
		t.Fatalf("VerifyEmail() error: %v", err)
	}
	if !fx.users.byID[u.ID].EmailVerified {
		t.Error("user not verified after VerifyEmail")
	}
	// Single use.
	if err := fx.svc.VerifyEmail(ctx, tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyEmail(reused) error = %v, want ErrInvalidToken", err)
	}

	got, err := fx.svc.Login(ctx, "sri@example.com", "hunter2hunter2")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("Login() user = %v, want %v", got.ID, u.ID)
	}
}

func TestLoginGenericFailures(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	u := fx.signup(t, "sri@example.com", "hunter2hunter2")
	fx.users.byID[u.ID].EmailVerified = true

	// Wrong password and unknown email yield the same error.
	if _, err := fx.svc.Login(ctx, "sri@example.com", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login(wrong pw) error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := fx.svc.Login(ctx, "ghost@example.com", "whatever-pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login(unknown) error = %v, want ErrInvalidCredentials", err)
	}

	// OAuth-only account (no credential row) is also indistinguishable.
	oauthUser := &model.User{Email: "oauth@example.com", EmailVerified: true}
	if err := fx.users.Create(ctx, oauthUser); err != nil {
		t.Fatalf("create oauth user: %v", err)
	}
	if _, err := fx.svc.Login(ctx, "oauth@example.com", "whatever-pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login(oauth-only) error = %v, want ErrInvalidCredentials", err)
	}
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	fx := newFixture(t)
	fx.svc.now = func() time.Time { return time.Now().Add(-25 * time.Hour) } // token created 25h ago
	fx.signup(t, "sri@example.com", "hunter2hunter2")
	tok := fx.tokenFromLink(t)

	fx.svc.now = time.Now
	if err := fx.svc.VerifyEmail(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyEmail(expired) error = %v, want ErrInvalidToken", err)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	u := fx.signup(t, "sri@example.com", "old-password-1")
	fx.users.byID[u.ID].EmailVerified = true
	emailsBefore := fx.email.count()

	// Unknown email: success, no email, no token.
	if err := fx.svc.RequestPasswordReset(ctx, "ghost@example.com"); err != nil {
		t.Fatalf("RequestPasswordReset(unknown) error: %v", err)
	}
	fx.svc.Wait()
	if fx.email.count() != emailsBefore {
		t.Error("reset email sent for unknown account")
	}

	// Known email: reset email in background.
	if err := fx.svc.RequestPasswordReset(ctx, "sri@example.com"); err != nil {
		t.Fatalf("RequestPasswordReset() error: %v", err)
	}
	fx.svc.Wait()
	if fx.email.count() != emailsBefore+1 {
		t.Fatalf("emails sent = %d, want %d", fx.email.count(), emailsBefore+1)
	}
	if !strings.Contains(fx.email.last().html, "http://spa.test/reset-password?token=") {
		t.Errorf("email missing reset link: %q", fx.email.last().html)
	}

	tok := fx.tokenFromLink(t)

	// A reset token must not verify an email (purpose scoping).
	if err := fx.svc.VerifyEmail(ctx, tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyEmail(reset token) error = %v, want ErrInvalidToken", err)
	}

	if err := fx.svc.ResetPassword(ctx, tok, "new-password-1"); err != nil {
		t.Fatalf("ResetPassword() error: %v", err)
	}

	// All sessions revoked; old password dead; new password works.
	if len(fx.refresh.revokedUsers) != 1 || fx.refresh.revokedUsers[0] != u.ID {
		t.Errorf("revoked users = %v, want [%v]", fx.refresh.revokedUsers, u.ID)
	}
	if _, err := fx.svc.Login(ctx, "sri@example.com", "old-password-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login(old pw) error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := fx.svc.Login(ctx, "sri@example.com", "new-password-1"); err != nil {
		t.Errorf("Login(new pw) error: %v", err)
	}

	// Token is single use.
	if err := fx.svc.ResetPassword(ctx, tok, "another-password-1"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ResetPassword(reused) error = %v, want ErrInvalidToken", err)
	}
	// Weak new password rejected before consuming the token.
	if err := fx.svc.ResetPassword(ctx, "any", "short"); !errors.Is(err, ErrPasswordPolicy) {
		t.Errorf("ResetPassword(weak) error = %v, want ErrPasswordPolicy", err)
	}
}

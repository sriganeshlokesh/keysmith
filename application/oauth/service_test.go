package oauth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/domain/model"
	"github.com/sriganeshlokesh/keysmith/domain/repo"
)

// ── Fakes ──────────────────────────────────────────────────────────────────────

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
func (f *fakeUsers) SetEmailVerified(context.Context, uuid.UUID, bool) error { return nil }

type identityKey struct {
	provider model.Provider
	subject  string
}

type fakeIdentities struct {
	rows map[identityKey]*model.Identity
	// raceWith, when set, simulates a concurrent request winning identity
	// creation: Create inserts this row and reports a duplicate.
	raceWith *model.Identity
}

func (f *fakeIdentities) Create(_ context.Context, id *model.Identity) error {
	key := identityKey{id.Provider, id.ProviderUserID}
	if f.raceWith != nil {
		f.rows[identityKey{f.raceWith.Provider, f.raceWith.ProviderUserID}] = f.raceWith
		f.raceWith = nil
		return model.ErrDuplicateIdentity
	}
	if _, exists := f.rows[key]; exists {
		return model.ErrDuplicateIdentity
	}
	id.ID = uuid.New()
	id.CreatedAt = time.Now()
	f.rows[key] = id
	return nil
}
func (f *fakeIdentities) GetByProvider(_ context.Context, provider model.Provider, subject string) (*model.Identity, error) {
	id, ok := f.rows[identityKey{provider, subject}]
	if !ok {
		return nil, model.ErrNotFound
	}
	return id, nil
}

var (
	_ repo.Users      = (*fakeUsers)(nil)
	_ repo.Identities = (*fakeIdentities)(nil)
)

// fakeProvider returns canned claims, standing in for Google.
type fakeProvider struct {
	claims *ProviderClaims
	err    error
}

func (f *fakeProvider) Name() model.Provider { return model.ProviderGoogle }
func (f *fakeProvider) AuthCodeURL(state, nonce, verifier string) string {
	return "https://provider.test/authorize?state=" + state + "&nonce=" + nonce + "&verifier=" + verifier
}
func (f *fakeProvider) Exchange(context.Context, string, string, string) (*ProviderClaims, error) {
	return f.claims, f.err
}

// ── Fixture ────────────────────────────────────────────────────────────────────

type fixture struct {
	svc        *Service
	users      *fakeUsers
	identities *fakeIdentities
	provider   *fakeProvider
}

func newFixture(claims *ProviderClaims) *fixture {
	fx := &fixture{
		users:      &fakeUsers{byID: map[uuid.UUID]*model.User{}},
		identities: &fakeIdentities{rows: map[identityKey]*model.Identity{}},
		provider:   &fakeProvider{claims: claims},
	}
	fx.svc = NewService(
		map[model.Provider]IdentityProvider{model.ProviderGoogle: fx.provider},
		fx.users, fx.identities, slog.New(slog.DiscardHandler),
	)
	return fx
}

// callback runs the standard valid-state callback.
func (fx *fixture) callback(t *testing.T) (*model.User, error) {
	t.Helper()
	return fx.svc.Callback(context.Background(), model.ProviderGoogle, CallbackParams{
		Code: "code", State: "st", ExpectedState: "st", Nonce: "n", PKCEVerifier: "v",
	})
}

func (fx *fixture) addUser(t *testing.T, email string, verified bool) *model.User {
	t.Helper()
	u := &model.User{Email: email, EmailVerified: verified}
	if err := fx.users.Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func (fx *fixture) addIdentity(t *testing.T, userID uuid.UUID, subject string) {
	t.Helper()
	err := fx.identities.Create(context.Background(),
		&model.Identity{UserID: userID, Provider: model.ProviderGoogle, ProviderUserID: subject})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
}

// ── Begin / state tests ────────────────────────────────────────────────────────

func TestBegin(t *testing.T) {
	fx := newFixture(nil)

	res, err := fx.svc.Begin(model.ProviderGoogle)
	if err != nil {
		t.Fatalf("Begin() error: %v", err)
	}
	if res.State == "" || res.Nonce == "" || res.PKCEVerifier == "" {
		t.Errorf("Begin() = %+v, want all secrets non-empty", res)
	}
	for _, part := range []string{res.State, res.Nonce, res.PKCEVerifier} {
		if !strings.Contains(res.RedirectURL, part) {
			t.Errorf("redirect URL missing %q: %s", part, res.RedirectURL)
		}
	}

	if _, err := fx.svc.Begin(model.ProviderLinkedIn); !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("Begin(unconfigured) error = %v, want ErrUnknownProvider", err)
	}
}

func TestCallback_StateMismatch(t *testing.T) {
	fx := newFixture(&ProviderClaims{Subject: "s", Email: "a@b.c", EmailVerified: true})

	tests := []struct {
		name     string
		state    string
		expected string
	}{
		{name: "different", state: "attacker", expected: "victim"},
		{name: "empty query state", state: "", expected: "st"},
		{name: "empty cookie state", state: "st", expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fx.svc.Callback(context.Background(), model.ProviderGoogle, CallbackParams{
				Code: "code", State: tt.state, ExpectedState: tt.expected,
			})
			if !errors.Is(err, ErrStateMismatch) {
				t.Errorf("Callback() error = %v, want ErrStateMismatch", err)
			}
		})
	}
}

// ── Linking rules (master plan §6) ─────────────────────────────────────────────

func TestLinkingRule1_ExistingIdentity(t *testing.T) {
	fx := newFixture(&ProviderClaims{Subject: "li-sub-1", Email: "sri@example.com", EmailVerified: true})
	existing := fx.addUser(t, "sri@example.com", true)
	fx.addIdentity(t, existing.ID, "li-sub-1")

	got, err := fx.callback(t)
	if err != nil {
		t.Fatalf("Callback() error: %v", err)
	}
	if got.ID != existing.ID {
		t.Errorf("resolved user = %v, want existing %v", got.ID, existing.ID)
	}
	if len(fx.users.byID) != 1 || len(fx.identities.rows) != 1 {
		t.Error("rule 1 must not create new rows")
	}
}

func TestLinkingRule2_VerifiedEmailAutoLinks(t *testing.T) {
	// Existing password user; first LinkedIn login with the same, verified email.
	fx := newFixture(&ProviderClaims{Subject: "li-sub-2", Email: "Sri@Example.com", EmailVerified: true})
	existing := fx.addUser(t, "sri@example.com", true) // case differs — must still match

	got, err := fx.callback(t)
	if err != nil {
		t.Fatalf("Callback() error: %v", err)
	}
	if got.ID != existing.ID {
		t.Errorf("resolved user = %v, want linked existing %v", got.ID, existing.ID)
	}
	ident, err := fx.identities.GetByProvider(context.Background(), model.ProviderGoogle, "li-sub-2")
	if err != nil {
		t.Fatalf("identity not created: %v", err)
	}
	if ident.UserID != existing.ID {
		t.Errorf("identity linked to %v, want %v", ident.UserID, existing.ID)
	}
	if len(fx.users.byID) != 1 {
		t.Error("rule 2 must not create a new user")
	}
}

func TestLinkingRule3_UnverifiedEmailNeverAutoLinks(t *testing.T) {
	// Unverified provider email with NO existing user → new unverified user.
	fx := newFixture(&ProviderClaims{Subject: "li-sub-3", Email: "new@example.com", EmailVerified: false})

	got, err := fx.callback(t)
	if err != nil {
		t.Fatalf("Callback() error: %v", err)
	}
	if got.EmailVerified {
		t.Error("user from unverified provider email must start unverified")
	}
	if len(fx.users.byID) != 1 {
		t.Errorf("users = %d, want 1 new", len(fx.users.byID))
	}
}

func TestLinkingRule3_UnverifiedCollisionRejected(t *testing.T) {
	// Unverified provider email that MATCHES an existing user → hard reject.
	fx := newFixture(&ProviderClaims{Subject: "li-sub-4", Email: "sri@example.com", EmailVerified: false})
	existing := fx.addUser(t, "sri@example.com", true)

	_, err := fx.callback(t)
	if !errors.Is(err, ErrEmailConflict) {
		t.Fatalf("Callback() error = %v, want ErrEmailConflict", err)
	}
	if _, err := fx.identities.GetByProvider(context.Background(), model.ProviderGoogle, "li-sub-4"); !errors.Is(err, model.ErrNotFound) {
		t.Error("identity must not be linked on unverified collision")
	}
	if len(fx.users.byID) != 1 || fx.users.byID[existing.ID] == nil {
		t.Error("existing user must be untouched")
	}
}

func TestLinkingRule4_NewUserFromVerifiedEmail(t *testing.T) {
	fx := newFixture(&ProviderClaims{
		Subject: "li-sub-5", Email: "fresh@example.com", EmailVerified: true,
		Name: "Sri L", Picture: "https://img.test/p.jpg",
	})

	got, err := fx.callback(t)
	if err != nil {
		t.Fatalf("Callback() error: %v", err)
	}
	if !got.EmailVerified {
		t.Error("user from verified provider email must be verified")
	}
	if got.Name == nil || *got.Name != "Sri L" {
		t.Errorf("Name = %v, want Sri L", got.Name)
	}
	if got.AvatarURL == nil || *got.AvatarURL != "https://img.test/p.jpg" {
		t.Errorf("AvatarURL = %v", got.AvatarURL)
	}
	if _, err := fx.identities.GetByProvider(context.Background(), model.ProviderGoogle, "li-sub-5"); err != nil {
		t.Errorf("identity not created: %v", err)
	}
}

// ── Edge cases ─────────────────────────────────────────────────────────────────

func TestCallback_NoEmail(t *testing.T) {
	fx := newFixture(&ProviderClaims{Subject: "li-sub-6", Email: ""})
	if _, err := fx.callback(t); !errors.Is(err, ErrNoEmail) {
		t.Errorf("Callback() error = %v, want ErrNoEmail", err)
	}
}

func TestCallback_ExchangeError(t *testing.T) {
	fx := newFixture(nil)
	fx.provider.err = errors.New("provider exploded")
	if _, err := fx.callback(t); err == nil {
		t.Error("Callback() succeeded despite exchange failure")
	}
}

func TestCallback_IdentityRaceFollowsWinner(t *testing.T) {
	// The identity appears between our lookup miss and our create — the
	// duplicate error must resolve to whichever user won the race.
	fx := newFixture(&ProviderClaims{Subject: "li-sub-7", Email: "race@example.com", EmailVerified: true})
	winner := fx.addUser(t, "winner@example.com", true)
	fx.identities.raceWith = &model.Identity{
		ID: uuid.New(), UserID: winner.ID,
		Provider: model.ProviderGoogle, ProviderUserID: "li-sub-7",
	}

	got, err := fx.callback(t)
	if err != nil {
		t.Fatalf("Callback() error: %v", err)
	}
	if got.ID != winner.ID {
		t.Errorf("resolved user = %v, want race winner %v", got.ID, winner.ID)
	}
}

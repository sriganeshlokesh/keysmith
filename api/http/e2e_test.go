package http_test

// End-to-end tests for the Phase 3 acceptance criteria: the full password
// flow over real HTTP against real Postgres, refresh rotation + reuse
// revocation, reset revoking all sessions, no user enumeration, and per-IP
// rate limits. Skipped unless TEST_DATABASE_URL is set (make test-integration).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/sriganeshlokesh/keysmith/adapter/repository/postgres"
	apihttp "github.com/sriganeshlokesh/keysmith/api/http"
	"github.com/sriganeshlokesh/keysmith/api/http/handle"
	"github.com/sriganeshlokesh/keysmith/application/oauth"
	"github.com/sriganeshlokesh/keysmith/application/password"
	"github.com/sriganeshlokesh/keysmith/application/token"
	"github.com/sriganeshlokesh/keysmith/config"
	"github.com/sriganeshlokesh/keysmith/domain/service"
)

type sentEmail struct {
	to      string
	subject string
	html    string
}

type captureSender struct {
	mu   sync.Mutex
	sent []sentEmail
}

func (c *captureSender) Send(_ context.Context, to, subject, html string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, sentEmail{to: to, subject: subject, html: html})
	return nil
}

func (c *captureSender) lastHTML(t *testing.T) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sent) == 0 {
		t.Fatal("no emails captured")
	}
	return c.sent[len(c.sent)-1].html
}

var tokenRe = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

func extractToken(t *testing.T, html string) string {
	t.Helper()
	m := tokenRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no token link in email: %q", html)
	}
	return m[1]
}

type env struct {
	ts    *httptest.Server
	pwSvc *password.Service
	email *captureSender
}

// newEnv assembles the real stack — repos, services, handlers, router — on a
// clean database with a fresh rate-limiter state per test.
func newEnv(t *testing.T) *env {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; run integration tests with `make test-integration`")
	}
	ctx := context.Background()

	if err := postgres.Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := &config.Config{
		ServiceName:     "keysmith",
		Env:             "local",
		Version:         "test",
		PublicBaseURL:   "http://auth.test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 720 * time.Hour,
		DatabaseURL:     url,
	}
	pool, cleanup, err := postgres.NewPool(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(cleanup)
	if _, err := pool.Exec(ctx,
		`TRUNCATE users, identities, password_credentials, refresh_tokens, one_time_tokens CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := service.NewSigner([]service.SigningKey{{Kid: "e2e", PrivateKey: priv}})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	logger := slog.New(slog.DiscardHandler)
	users := postgres.NewUserRepo(pool)
	identities := postgres.NewIdentityRepo(pool)
	creds := postgres.NewCredentialRepo(pool)
	oneTime := postgres.NewOneTimeTokenRepo(pool)
	refresh := postgres.NewRefreshTokenRepo(pool)

	tokenSvc := token.NewService(signer, users, refresh,
		token.Config{Issuer: cfg.PublicBaseURL, AccessTTL: cfg.AccessTokenTTL, RefreshTTL: cfg.RefreshTokenTTL}, logger)
	email := &captureSender{}
	pwSvc, err := password.NewService(users, creds, oneTime, refresh, email,
		password.Config{SPAOrigin: "http://spa.test"}, logger)
	if err != nil {
		t.Fatalf("password service: %v", err)
	}

	oauthSvc := oauth.NewService(nil, users, identities, logger)
	router := apihttp.NewRouter(cfg, logger,
		handle.NewHealthHandler(cfg, pool),
		handle.NewJWKSHandler(signer),
		handle.NewPasswordHandler(cfg, pwSvc, tokenSvc),
		handle.NewSessionHandler(cfg, tokenSvc),
		handle.NewMeHandler(users),
		handle.NewOAuthHandler(cfg, oauthSvc, tokenSvc, logger),
		signer,
	)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	return &env{ts: ts, pwSvc: pwSvc, email: email}
}

func (e *env) post(t *testing.T, path string, body any, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (e *env) getMe(t *testing.T, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+"/auth/me", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /auth/me: %v", err)
	}
	return resp
}

func refreshCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == "keysmith_refresh" && c.Value != "" {
			return c
		}
	}
	t.Fatal("no keysmith_refresh cookie in response")
	return nil
}

func decodeBody[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return v
}

type sessionBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, want, body)
	}
}

// signupVerifyLogin walks a user to a live session and returns the access
// token and refresh cookie.
func signupVerifyLogin(t *testing.T, e *env, email, pw string) (string, *http.Cookie) {
	t.Helper()
	resp := e.post(t, "/auth/signup", map[string]string{"email": email, "password": pw})
	wantStatus(t, resp, http.StatusCreated)
	_ = resp.Body.Close()

	verifyToken := extractToken(t, e.email.lastHTML(t))
	resp = e.post(t, "/auth/verify-email", map[string]string{"token": verifyToken})
	wantStatus(t, resp, http.StatusOK)
	_ = resp.Body.Close()

	resp = e.post(t, "/auth/login", map[string]string{"email": email, "password": pw})
	wantStatus(t, resp, http.StatusOK)
	cookie := refreshCookie(t, resp)
	sess := decodeBody[sessionBody](t, resp)
	if sess.AccessToken == "" || sess.TokenType != "Bearer" {
		t.Fatalf("bad session body: %+v", sess)
	}
	return sess.AccessToken, cookie
}

// TestFullPasswordFlow is the Phase 3 acceptance test:
// signup → verify email link → login → refresh → me → logout.
func TestFullPasswordFlow(t *testing.T) {
	e := newEnv(t)

	// Signup, then login before verification must 403.
	resp := e.post(t, "/auth/signup", map[string]string{"email": "sri@example.com", "password": "hunter2hunter2"})
	wantStatus(t, resp, http.StatusCreated)
	_ = resp.Body.Close()
	resp = e.post(t, "/auth/login", map[string]string{"email": "sri@example.com", "password": "hunter2hunter2"})
	wantStatus(t, resp, http.StatusForbidden)
	_ = resp.Body.Close()

	// Verify via the emailed link, then login.
	verifyToken := extractToken(t, e.email.lastHTML(t))
	resp = e.post(t, "/auth/verify-email", map[string]string{"token": verifyToken})
	wantStatus(t, resp, http.StatusOK)
	_ = resp.Body.Close()
	resp = e.post(t, "/auth/login", map[string]string{"email": "sri@example.com", "password": "hunter2hunter2"})
	wantStatus(t, resp, http.StatusOK)
	access := decodeBody[sessionBody](t, resp).AccessToken
	cookie := refreshCookie(t, resp)

	// Me with the access token.
	me := e.getMe(t, access)
	wantStatus(t, me, http.StatusOK)
	profile := decodeBody[map[string]any](t, me)
	if profile["email"] != "sri@example.com" || profile["email_verified"] != true {
		t.Errorf("me = %v", profile)
	}
	// Me without a token is rejected.
	anon := e.getMe(t, "")
	wantStatus(t, anon, http.StatusUnauthorized)
	_ = anon.Body.Close()

	// Refresh rotates: new access token works, cookie value changes.
	resp = e.post(t, "/auth/refresh", nil, cookie)
	wantStatus(t, resp, http.StatusOK)
	newCookie := refreshCookie(t, resp)
	newAccess := decodeBody[sessionBody](t, resp).AccessToken
	if newCookie.Value == cookie.Value {
		t.Error("refresh did not rotate the cookie token")
	}
	me = e.getMe(t, newAccess)
	wantStatus(t, me, http.StatusOK)
	_ = me.Body.Close()

	// Logout revokes and clears; the cookie no longer refreshes.
	resp = e.post(t, "/auth/logout", nil, newCookie)
	wantStatus(t, resp, http.StatusOK)
	_ = resp.Body.Close()
	resp = e.post(t, "/auth/refresh", nil, newCookie)
	wantStatus(t, resp, http.StatusUnauthorized)
	_ = resp.Body.Close()
}

// TestRefreshReuseRevokesFamily replays a rotated-out cookie and expects the
// whole family dead (master plan §5).
func TestRefreshReuseRevokesFamily(t *testing.T) {
	e := newEnv(t)
	_, first := signupVerifyLogin(t, e, "reuse@example.com", "hunter2hunter2")

	resp := e.post(t, "/auth/refresh", nil, first)
	wantStatus(t, resp, http.StatusOK)
	second := refreshCookie(t, resp)
	_ = resp.Body.Close()

	// Replay the first (rotated-out) token.
	resp = e.post(t, "/auth/refresh", nil, first)
	wantStatus(t, resp, http.StatusUnauthorized)
	_ = resp.Body.Close()

	// The current token is now dead too.
	resp = e.post(t, "/auth/refresh", nil, second)
	wantStatus(t, resp, http.StatusUnauthorized)
	_ = resp.Body.Close()
}

// TestPasswordResetRevokesSessions covers the reset acceptance criteria.
func TestPasswordResetRevokesSessions(t *testing.T) {
	e := newEnv(t)
	_, cookie := signupVerifyLogin(t, e, "reset@example.com", "old-password-1")

	// Unknown and known emails get identical responses.
	respUnknown := e.post(t, "/auth/request-password-reset", map[string]string{"email": "ghost@example.com"})
	wantStatus(t, respUnknown, http.StatusOK)
	unknownBody, _ := io.ReadAll(respUnknown.Body)
	_ = respUnknown.Body.Close()

	respKnown := e.post(t, "/auth/request-password-reset", map[string]string{"email": "reset@example.com"})
	wantStatus(t, respKnown, http.StatusOK)
	knownBody, _ := io.ReadAll(respKnown.Body)
	_ = respKnown.Body.Close()
	if !bytes.Equal(unknownBody, knownBody) {
		t.Errorf("reset responses differ: %s vs %s", unknownBody, knownBody)
	}

	e.pwSvc.Wait() // reset email is sent in the background
	resetToken := extractToken(t, e.email.lastHTML(t))
	resp := e.post(t, "/auth/reset-password", map[string]string{"token": resetToken, "new_password": "new-password-1"})
	wantStatus(t, resp, http.StatusOK)
	_ = resp.Body.Close()

	// Every pre-reset session is revoked.
	resp = e.post(t, "/auth/refresh", nil, cookie)
	wantStatus(t, resp, http.StatusUnauthorized)
	_ = resp.Body.Close()

	// Old password dead, new password lives.
	resp = e.post(t, "/auth/login", map[string]string{"email": "reset@example.com", "password": "old-password-1"})
	wantStatus(t, resp, http.StatusUnauthorized)
	_ = resp.Body.Close()
	resp = e.post(t, "/auth/login", map[string]string{"email": "reset@example.com", "password": "new-password-1"})
	wantStatus(t, resp, http.StatusOK)
	_ = resp.Body.Close()
}

// TestNoUserEnumeration compares login failures for a wrong password vs an
// unknown account: byte-identical bodies and equal status codes.
func TestNoUserEnumeration(t *testing.T) {
	e := newEnv(t)
	signupVerifyLogin(t, e, "real@example.com", "hunter2hunter2")

	wrongPw := e.post(t, "/auth/login", map[string]string{"email": "real@example.com", "password": "wrong-password"})
	unknown := e.post(t, "/auth/login", map[string]string{"email": "ghost@example.com", "password": "wrong-password"})

	if wrongPw.StatusCode != unknown.StatusCode {
		t.Errorf("status codes differ: %d vs %d", wrongPw.StatusCode, unknown.StatusCode)
	}
	a, _ := io.ReadAll(wrongPw.Body)
	b, _ := io.ReadAll(unknown.Body)
	_ = wrongPw.Body.Close()
	_ = unknown.Body.Close()
	if !bytes.Equal(a, b) {
		t.Errorf("bodies differ: %s vs %s", a, b)
	}
}

// TestLoginRateLimit exercises the 10/min per-IP cap on /auth/login.
func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)

	var last int
	for i := 0; i < 11; i++ {
		resp := e.post(t, "/auth/login", map[string]string{"email": "ghost@example.com", "password": "whatever-pw"})
		last = resp.StatusCode
		_ = resp.Body.Close()
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("11th login status = %d, want 429", last)
	}
}

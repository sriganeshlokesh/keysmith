package handle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/sriganeshlokesh/keysmith/application/oauth"
	"github.com/sriganeshlokesh/keysmith/application/token"
	"github.com/sriganeshlokesh/keysmith/config"
	"github.com/sriganeshlokesh/keysmith/domain/model"
)

type fakeOAuthSvc struct {
	begin       *oauth.BeginResult
	beginErr    error
	user        *model.User
	callbackErr error
	gotParams   oauth.CallbackParams
}

func (f *fakeOAuthSvc) Begin(model.Provider) (*oauth.BeginResult, error) {
	return f.begin, f.beginErr
}
func (f *fakeOAuthSvc) Callback(_ context.Context, _ model.Provider, p oauth.CallbackParams) (*model.User, error) {
	f.gotParams = p
	return f.user, f.callbackErr
}

type fakeIssuer struct{}

func (fakeIssuer) IssueSession(context.Context, *model.User) (*token.Session, error) {
	return &token.Session{
		AccessToken:      "access",
		AccessExpiresAt:  time.Now().Add(15 * time.Minute),
		RefreshToken:     "refresh-raw",
		RefreshExpiresAt: time.Now().Add(720 * time.Hour),
	}, nil
}

func newOAuthRouter(svc *fakeOAuthSvc) http.Handler {
	cfg := &config.Config{Env: "local", SPAOrigin: "http://spa.test", ServiceName: "keysmith"}
	h := NewOAuthHandler(cfg, svc, fakeIssuer{}, slog.New(slog.DiscardHandler))
	r := chi.NewRouter()
	r.Get("/auth/{provider}/login", h.Login)
	r.Get("/auth/{provider}/callback", h.Callback)
	return r
}

func stateCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookie && c.Value != "" {
			return c
		}
	}
	t.Fatal("no oauth state cookie set")
	return nil
}

func TestOAuthLogin_SetsStateCookieAndRedirects(t *testing.T) {
	svc := &fakeOAuthSvc{begin: &oauth.BeginResult{
		RedirectURL: "https://provider.test/authorize?x=1",
		State:       "st-1", Nonce: "n-1", PKCEVerifier: "v-1",
	}}
	router := newOAuthRouter(svc)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/google/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://provider.test/authorize?x=1" {
		t.Errorf("Location = %q", loc)
	}

	cookie := stateCookieFrom(t, rec)
	if !cookie.HttpOnly || cookie.Path != "/auth" {
		t.Errorf("state cookie attrs = %+v, want HttpOnly Path=/auth", cookie)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatalf("decode state cookie: %v", err)
	}
	var st oauthStatePayload
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("unmarshal state cookie: %v", err)
	}
	if st.State != "st-1" || st.Nonce != "n-1" || st.Verifier != "v-1" || st.Provider != "google" {
		t.Errorf("state payload = %+v", st)
	}
}

func TestOAuthLogin_UnknownProvider(t *testing.T) {
	router := newOAuthRouter(&fakeOAuthSvc{})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/github/login", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unsupported provider", rec.Code)
	}

	svc := &fakeOAuthSvc{beginErr: oauth.ErrUnknownProvider}
	router = newOAuthRouter(svc)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/google/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unconfigured provider", rec.Code)
	}
}

func TestOAuthCallback_Success(t *testing.T) {
	svc := &fakeOAuthSvc{
		begin: &oauth.BeginResult{RedirectURL: "https://provider.test/a", State: "st-1", Nonce: "n-1", PKCEVerifier: "v-1"},
		user:  &model.User{ID: uuid.New(), Email: "sri@example.com"},
	}
	router := newOAuthRouter(svc)

	// Get the state cookie from the login leg.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/google/login", nil))
	stateCookie := stateCookieFrom(t, rec)

	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=c-1&state=st-1", nil)
	req.AddCookie(stateCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://spa.test/auth/complete" {
		t.Errorf("Location = %q, want SPA /auth/complete", loc)
	}
	// The cookie secrets must reach the service verbatim.
	want := oauth.CallbackParams{Code: "c-1", State: "st-1", ExpectedState: "st-1", Nonce: "n-1", PKCEVerifier: "v-1"}
	if svc.gotParams != want {
		t.Errorf("params = %+v, want %+v", svc.gotParams, want)
	}

	var gotRefresh, clearedState bool
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case "keysmith_refresh":
			gotRefresh = c.Value == "refresh-raw" && c.HttpOnly && c.Path == "/auth"
		case oauthStateCookie:
			clearedState = c.MaxAge < 0
		}
	}
	if !gotRefresh {
		t.Error("refresh cookie not set correctly on callback")
	}
	if !clearedState {
		t.Error("state cookie not cleared on callback")
	}
}

func TestOAuthCallback_Failures(t *testing.T) {
	user := &model.User{ID: uuid.New(), Email: "sri@example.com"}
	mkCookie := func(provider, state string) *http.Cookie {
		payload, _ := json.Marshal(oauthStatePayload{Provider: provider, State: state, Nonce: "n", Verifier: "v"})
		return &http.Cookie{Name: oauthStateCookie, Value: base64.RawURLEncoding.EncodeToString(payload)}
	}

	tests := []struct {
		name      string
		url       string
		cookie    *http.Cookie
		svc       *fakeOAuthSvc
		wantError string
	}{
		{
			name: "missing state cookie",
			url:  "/auth/google/callback?code=c&state=st",
			svc:  &fakeOAuthSvc{user: user}, wantError: "missing_state",
		},
		{
			name:   "cookie for wrong provider",
			url:    "/auth/google/callback?code=c&state=st",
			cookie: mkCookie("linkedin", "st"),
			svc:    &fakeOAuthSvc{user: user}, wantError: "invalid_state",
		},
		{
			name:   "provider returned error",
			url:    "/auth/google/callback?error=access_denied",
			cookie: mkCookie("google", "st"),
			svc:    &fakeOAuthSvc{user: user}, wantError: "provider_denied",
		},
		{
			name:   "state mismatch from service",
			url:    "/auth/google/callback?code=c&state=tampered",
			cookie: mkCookie("google", "st"),
			svc:    &fakeOAuthSvc{callbackErr: oauth.ErrStateMismatch}, wantError: "oauth_failed",
		},
		{
			name:   "unverified email conflict",
			url:    "/auth/google/callback?code=c&state=st",
			cookie: mkCookie("google", "st"),
			svc:    &fakeOAuthSvc{callbackErr: oauth.ErrEmailConflict}, wantError: "email_in_use",
		},
		{
			name:   "no email from provider",
			url:    "/auth/google/callback?code=c&state=st",
			cookie: mkCookie("google", "st"),
			svc:    &fakeOAuthSvc{callbackErr: oauth.ErrNoEmail}, wantError: "no_email",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newOAuthRouter(tt.svc)
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", rec.Code)
			}
			want := "http://spa.test/login?error=" + tt.wantError
			if loc := rec.Header().Get("Location"); loc != want {
				t.Errorf("Location = %q, want %q", loc, want)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == "keysmith_refresh" && c.Value != "" {
					t.Error("refresh cookie set on failed callback")
				}
			}
		})
	}
}

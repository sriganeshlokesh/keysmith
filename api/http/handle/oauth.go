package handle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sriganeshlokesh/keysmith/api/error_code"
	"github.com/sriganeshlokesh/keysmith/application/oauth"
	"github.com/sriganeshlokesh/keysmith/config"
	"github.com/sriganeshlokesh/keysmith/domain/model"
)

// OAuthService is what this handler needs from the OAuth use cases.
// Satisfied implicitly by *oauth.Service.
type OAuthService interface {
	Begin(provider model.Provider) (*oauth.BeginResult, error)
	Callback(ctx context.Context, provider model.Provider, params oauth.CallbackParams) (*model.User, error)
}

// OAuthHandler serves GET /auth/{provider}/login and /auth/{provider}/callback.
type OAuthHandler struct {
	svc      OAuthService
	sessions SessionIssuer
	cfg      *config.Config
	logger   *slog.Logger
}

// NewOAuthHandler constructs an OAuthHandler.
func NewOAuthHandler(cfg *config.Config, svc OAuthService, sessions SessionIssuer, logger *slog.Logger) *OAuthHandler {
	return &OAuthHandler{svc: svc, sessions: sessions, cfg: cfg, logger: logger}
}

// oauthStateCookie carries the per-attempt secrets between the login redirect
// and the callback. HttpOnly + short-lived; Path=/auth covers the callback.
const oauthStateCookie = "keysmith_oauth"

const stateCookieTTLSeconds = 600

// oauthStatePayload is the JSON stored (base64) in the state cookie.
type oauthStatePayload struct {
	Provider string `json:"provider"`
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

// Login handles GET /auth/{provider}/login: set the state cookie, 302 to the
// provider's consent screen.
func (h *OAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	provider, ok := parseProvider(chi.URLParam(r, "provider"))
	if !ok {
		writeError(w, error_code.ErrInvalidParams)
		return
	}
	begin, err := h.svc.Begin(provider)
	if err != nil {
		if errors.Is(err, oauth.ErrUnknownProvider) {
			writeError(w, error_code.New(error_code.ErrInvalidParams.Code, "provider not configured", http.StatusNotFound))
		} else {
			writeError(w, error_code.ErrInternal)
		}
		return
	}

	payload, err := json.Marshal(oauthStatePayload{
		Provider: string(provider),
		State:    begin.State,
		Nonce:    begin.Nonce,
		Verifier: begin.PKCEVerifier,
	})
	if err != nil {
		writeError(w, error_code.ErrInternal)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    base64.RawURLEncoding.EncodeToString(payload),
		Path:     "/auth",
		MaxAge:   stateCookieTTLSeconds,
		HttpOnly: true,
		Secure:   h.cfg.Env != "local",
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, begin.RedirectURL, http.StatusFound)
}

// Callback handles GET /auth/{provider}/callback: validate state, exchange
// the code, apply linking rules, start a session, and bounce to the SPA.
// Failures redirect to the SPA login page with an error code — the browser
// is mid-navigation here, so JSON errors would strand the user.
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	provider, ok := parseProvider(chi.URLParam(r, "provider"))
	if !ok {
		h.redirectError(w, r, "unknown_provider")
		return
	}

	stateCookie, err := r.Cookie(oauthStateCookie)
	clearStateCookie(w, h.cfg)
	if err != nil || stateCookie.Value == "" {
		h.redirectError(w, r, "missing_state")
		return
	}
	var st oauthStatePayload
	raw, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
	if err != nil || json.Unmarshal(raw, &st) != nil || st.Provider != string(provider) {
		h.redirectError(w, r, "invalid_state")
		return
	}

	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		// The user cancelled or the provider refused; not our failure.
		h.logger.Info("oauth callback returned provider error",
			slog.String("provider", string(provider)), slog.String("error", errCode))
		h.redirectError(w, r, "provider_denied")
		return
	}

	user, err := h.svc.Callback(r.Context(), provider, oauth.CallbackParams{
		Code:          q.Get("code"),
		State:         q.Get("state"),
		ExpectedState: st.State,
		Nonce:         st.Nonce,
		PKCEVerifier:  st.Verifier,
	})
	if err != nil {
		h.logger.Warn("oauth callback failed", "error", err,
			slog.String("provider", string(provider)))
		switch {
		case errors.Is(err, oauth.ErrEmailConflict):
			h.redirectError(w, r, "email_in_use")
		case errors.Is(err, oauth.ErrNoEmail):
			h.redirectError(w, r, "no_email")
		default:
			h.redirectError(w, r, "oauth_failed")
		}
		return
	}

	sess, err := h.sessions.IssueSession(r.Context(), user)
	if err != nil {
		h.logger.Error("failed to issue session after oauth", "error", err)
		h.redirectError(w, r, "oauth_failed")
		return
	}
	setRefreshCookie(w, h.cfg, sess.RefreshToken, sess.RefreshExpiresAt)
	http.Redirect(w, r, h.cfg.SPAOrigin+"/auth/complete", http.StatusFound)
}

func (h *OAuthHandler) redirectError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, h.cfg.SPAOrigin+"/login?error="+code, http.StatusFound)
}

func clearStateCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Env != "local",
		SameSite: http.SameSiteLaxMode,
	})
}

func parseProvider(raw string) (model.Provider, bool) {
	switch p := model.Provider(raw); p {
	case model.ProviderGoogle, model.ProviderLinkedIn:
		return p, true
	default:
		return "", false
	}
}

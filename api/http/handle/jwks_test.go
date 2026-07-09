package handle

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type staticJWKS []byte

func (s staticJWKS) JWKS() []byte { return s }

func TestJWKS(t *testing.T) {
	doc := `{"keys":[{"kty":"OKP","kid":"k1"}]}`
	h := NewJWKSHandler(staticJWKS(doc))

	rec := httptest.NewRecorder()
	h.JWKS(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != doc {
		t.Errorf("body = %q, want %q", got, doc)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want public, max-age=300", cc)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

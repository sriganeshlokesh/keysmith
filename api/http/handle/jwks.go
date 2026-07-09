package handle

import "net/http"

// JWKSProvider is what the JWKS handler needs from the signer.
// Declared here, at the consumer; satisfied implicitly by *service.Signer.
type JWKSProvider interface {
	JWKS() []byte
}

// JWKSHandler serves GET /.well-known/jwks.json so consuming services
// (forged via authkit) can verify access tokens locally (master plan §6).
type JWKSHandler struct {
	provider JWKSProvider
}

// NewJWKSHandler constructs a JWKSHandler.
func NewJWKSHandler(provider JWKSProvider) *JWKSHandler {
	return &JWKSHandler{provider: provider}
}

// JWKS writes the JWKS document. Cache-Control caps staleness at 5 minutes,
// bounding how long a rotated-out key keeps being trusted.
func (h *JWKSHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(h.provider.JWKS())
}

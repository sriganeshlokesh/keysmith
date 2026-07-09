package dependency

import (
	"fmt"
	"log/slog"

	"github.com/sriganeshlokesh/keysmith/config"
	"github.com/sriganeshlokesh/keysmith/domain/service"
)

// ProvideSigner decodes the configured signing keys into a domain Signer.
// The first configured key is the active signing key (master plan §5).
func ProvideSigner(cfg *config.Config, logger *slog.Logger) (*service.Signer, error) {
	if cfg.UsingDevSigningKeys {
		logger.Warn("using checked-in dev signing keys — local development only")
	}

	keys := make([]service.SigningKey, 0, len(cfg.SigningKeys))
	for _, k := range cfg.SigningKeys {
		priv, err := service.ParsePrivateKey(k.PrivateKeyB64)
		if err != nil {
			return nil, fmt.Errorf("signing key %q: %w", k.Kid, err)
		}
		keys = append(keys, service.SigningKey{Kid: k.Kid, PrivateKey: priv})
	}
	return service.NewSigner(keys)
}

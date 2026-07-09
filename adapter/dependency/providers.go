package dependency

import (
	"fmt"
	"log/slog"

	emailresend "github.com/sriganeshlokesh/keysmith/adapter/email/resend"
	emailsmtp "github.com/sriganeshlokesh/keysmith/adapter/email/smtp"
	"github.com/sriganeshlokesh/keysmith/application/password"
	"github.com/sriganeshlokesh/keysmith/application/token"
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

// ProvideTokenConfig maps app config onto the token service parameters.
func ProvideTokenConfig(cfg *config.Config) token.Config {
	return token.Config{
		Issuer:     cfg.PublicBaseURL,
		AccessTTL:  cfg.AccessTokenTTL,
		RefreshTTL: cfg.RefreshTokenTTL,
	}
}

// ProvidePasswordConfig maps app config onto the password service parameters.
func ProvidePasswordConfig(cfg *config.Config) password.Config {
	return password.Config{SPAOrigin: cfg.SPAOrigin}
}

// ProvideEmailSender selects the email transport at startup: Resend when an
// API key is configured, otherwise SMTP to mailpit — local dev only.
func ProvideEmailSender(cfg *config.Config, logger *slog.Logger) (password.EmailSender, error) {
	if cfg.ResendAPIKey != "" {
		logger.Info("using Resend email sender", slog.String("from", cfg.EmailFrom))
		return emailresend.New(cfg.ResendAPIKey, cfg.EmailFrom), nil
	}
	if cfg.Env == "local" {
		logger.Warn("RESEND_API_KEY not set — sending email via SMTP (mailpit)",
			slog.String("addr", cfg.SMTPAddr))
		return emailsmtp.New(cfg.SMTPAddr, cfg.EmailFrom), nil
	}
	return nil, fmt.Errorf("RESEND_API_KEY is required when ENV=%s", cfg.Env)
}

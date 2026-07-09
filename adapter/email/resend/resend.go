// Package resend delivers email through the Resend HTTP API (master plan §2).
package resend

import (
	"context"
	"fmt"

	"github.com/resend/resend-go/v2"
)

// Sender implements password.EmailSender over Resend.
type Sender struct {
	client *resend.Client
	from   string
}

// New constructs a Resend-backed sender. from must be a sender identity
// verified in the Resend dashboard (e.g. "Drafted <no-reply@domain>").
func New(apiKey, from string) *Sender {
	return &Sender{client: resend.NewClient(apiKey), from: from}
}

func (s *Sender) Send(ctx context.Context, to, subject, html string) error {
	_, err := s.client.Emails.SendWithContext(ctx, &resend.SendEmailRequest{
		From:    s.from,
		To:      []string{to},
		Subject: subject,
		Html:    html,
	})
	if err != nil {
		return fmt.Errorf("resend: %w", err)
	}
	return nil
}

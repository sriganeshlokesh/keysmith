// Package smtp delivers email over plain SMTP — local development only,
// where mailpit (docker-compose) catches everything on localhost:1025.
package smtp

import (
	"context"
	"fmt"
	"net/mail"
	"net/smtp"
	"strings"
)

// Sender implements password.EmailSender over unauthenticated SMTP.
type Sender struct {
	addr string
	from string
}

// New constructs an SMTP sender for the given address ("host:port").
func New(addr, from string) *Sender {
	return &Sender{addr: addr, from: from}
}

// Send delivers a single HTML email. net/smtp has no context support; the
// mailpit target is local, so blocking briefly is acceptable in dev.
func (s *Sender) Send(_ context.Context, to, subject, html string) error {
	fromAddr, err := mail.ParseAddress(s.from)
	if err != nil {
		return fmt.Errorf("smtp: invalid from address %q: %w", s.from, err)
	}

	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s\r\n", s.from)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(html)

	if err := smtp.SendMail(s.addr, nil, fromAddr.Address, []string{to}, []byte(msg.String())); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}

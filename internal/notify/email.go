package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/w512/SysRail/internal/core"
)

// SMTP transport security modes.
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "implicit"
	TLSNone     = "none"
)

// EmailConfig configures an email channel.
type EmailConfig struct {
	Host     string
	Port     int
	TLS      string // starttls (default), implicit or none
	Username string
	Password string
	From     string
	To       []string
	Events   []string
	// HelloName is sent in EHLO. Default: the notifier's host name.
	HelloName string
}

// Email sends messages over SMTP.
type Email struct {
	subscription
	c EmailConfig
}

// NewEmail returns an email channel.
func NewEmail(c EmailConfig) *Email {
	if c.TLS == "" {
		c.TLS = TLSStartTLS
	}
	if c.Port == 0 {
		c.Port = 587
		if c.TLS == TLSImplicit {
			c.Port = 465
		}
	}
	return &Email{subscription: newSubscription(c.Events), c: c}
}

func (e *Email) Name() string { return "email to " + strings.Join(e.c.To, ", ") }

func (e *Email) Send(ctx context.Context, m *Message) error {
	msg := e.render(m)
	addr := net.JoinHostPort(e.c.Host, strconv.Itoa(e.c.Port))
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := &net.Dialer{Deadline: deadline}
	tlsConfig := &tls.Config{ServerName: e.c.Host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	var err error
	if e.c.TLS == TLSImplicit {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return retryable(fmt.Errorf("connect to %s: %w", addr, err))
	}
	conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, e.c.Host)
	if err != nil {
		conn.Close()
		return smtpErr("greeting", err)
	}
	defer c.Close()
	hello := e.c.HelloName
	if hello == "" {
		hello = m.Host
	}
	if hello == "" {
		hello = "localhost"
	}
	if err := c.Hello(hello); err != nil {
		return smtpErr("EHLO", err)
	}
	if e.c.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return permanent(fmt.Errorf("%s does not offer STARTTLS; set tls: implicit or tls: none", addr))
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return smtpErr("STARTTLS", err)
		}
	}
	if e.c.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.c.Username, e.c.Password, e.c.Host)); err != nil {
			return smtpErr("authentication", err)
		}
	}
	if err := c.Mail(bareAddress(e.c.From)); err != nil {
		return smtpErr("MAIL FROM", err)
	}
	for _, to := range e.c.To {
		if err := c.Rcpt(bareAddress(to)); err != nil {
			return smtpErr("RCPT TO "+to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpErr("DATA", err)
	}
	if _, err := w.Write(msg); err != nil {
		return retryable(err)
	}
	if err := w.Close(); err != nil {
		return smtpErr("message", err)
	}
	if err := c.Quit(); err != nil {
		return smtpErr("QUIT", err)
	}
	return nil
}

// smtpErr retries temporary (4xx) failures and network errors, but not
// permanent (5xx) rejections.
func smtpErr(stage string, err error) error {
	wrapped := fmt.Errorf("smtp %s: %w", stage, err)
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 {
		return permanent(wrapped)
	}
	return retryable(wrapped)
}

func bareAddress(a string) string {
	if i, j := strings.LastIndex(a, "<"), strings.LastIndex(a, ">"); i >= 0 && j > i {
		return a[i+1 : j]
	}
	return strings.TrimSpace(a)
}

func headerSafe(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func (e *Email) render(m *Message) []byte {
	var b bytes.Buffer
	host := m.Host
	if host == "" {
		host = "localhost"
	}
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(e.c.From))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(e.c.To, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", headerSafe(m.Title)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", strings.ToLower(core.NewID("msg")), headerSafe(host))
	fmt.Fprintf(&b, "X-SysRail-Event: %s\r\n", headerSafe(m.Type))
	if m.Priority == "high" {
		b.WriteString("X-Priority: 2\r\n")
	}
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	body := strings.ReplaceAll(m.Text, "\n", "\r\n") + "\r\n\r\n-- \r\nSent by SysRail on " + host + "\r\n"
	qp.Write([]byte(body))
	qp.Close()
	return b.Bytes()
}

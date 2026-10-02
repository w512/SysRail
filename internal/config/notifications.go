package config

import (
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"

	"github.com/w512/SysRail/internal/core/events"
)

// Notifications configures where events are sent. Each channel subscribes to
// "events" (default: request.pending).
type Notifications struct {
	Webhooks []WebhookNotification  `yaml:"webhooks"`
	Ntfy     []NtfyNotification     `yaml:"ntfy"`
	Telegram []TelegramNotification `yaml:"telegram"`
	Email    []EmailNotification    `yaml:"email"`
}

// WebhookNotification posts JSON to a URL.
type WebhookNotification struct {
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
	Events  []string          `yaml:"events"`
}

// NtfyNotification publishes to an ntfy topic URL.
type NtfyNotification struct {
	URL    string   `yaml:"url"`
	Token  string   `yaml:"token"`
	Events []string `yaml:"events"`
}

// TelegramNotification sends messages through a Telegram bot.
type TelegramNotification struct {
	BotToken string   `yaml:"bot_token"`
	ChatID   string   `yaml:"chat_id"`
	APIURL   string   `yaml:"api_url"`
	Events   []string `yaml:"events"`
}

// EmailNotification sends email over SMTP.
type EmailNotification struct {
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	TLS      string   `yaml:"tls"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	Events   []string `yaml:"events"`
}

// Count returns the number of configured channels.
func (n Notifications) Count() int {
	return len(n.Webhooks) + len(n.Ntfy) + len(n.Telegram) + len(n.Email)
}

func (n Notifications) validate(fail func(string, ...any)) {
	checkEvents := func(where string, evs []string) {
		for _, e := range evs {
			if !slices.Contains(events.Types, e) {
				fail("%s: unknown event %q (known: %s)", where, e, strings.Join(events.Types, ", "))
			}
		}
	}
	checkURL := func(where, raw string, needPath bool) {
		u, err := url.Parse(raw)
		switch {
		case raw == "":
			fail("%s: url is required", where)
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			fail("%s: %q must be an absolute http(s) URL", where, raw)
		case needPath && strings.Trim(u.Path, "/") == "":
			fail("%s: %q must include the topic, e.g. https://ntfy.sh/my-topic", where, raw)
		}
	}
	for i, w := range n.Webhooks {
		where := fmt.Sprintf("notifications.webhooks[%d]", i)
		checkURL(where, w.URL, false)
		checkEvents(where, w.Events)
	}
	for i, c := range n.Ntfy {
		where := fmt.Sprintf("notifications.ntfy[%d]", i)
		checkURL(where, c.URL, true)
		checkEvents(where, c.Events)
	}
	for i, t := range n.Telegram {
		where := fmt.Sprintf("notifications.telegram[%d]", i)
		if t.BotToken == "" || strings.ContainsAny(t.BotToken, " /") {
			fail("%s: bot_token is required (from @BotFather)", where)
		}
		if t.ChatID == "" || strings.ContainsAny(t.ChatID, " /") {
			fail("%s: chat_id is required", where)
		}
		if t.APIURL != "" {
			checkURL(where+".api_url", t.APIURL, false)
		}
		checkEvents(where, t.Events)
	}
	for i, e := range n.Email {
		where := fmt.Sprintf("notifications.email[%d]", i)
		if e.SMTPHost == "" {
			fail("%s: smtp_host is required", where)
		}
		if e.SMTPPort < 0 || e.SMTPPort > 65535 {
			fail("%s: smtp_port must be 1-65535", where)
		}
		switch e.TLS {
		case "", "starttls", "implicit":
		case "none":
			if e.Username != "" || e.Password != "" {
				fail("%s: tls: none would send the password unencrypted; use starttls or implicit", where)
			}
		default:
			fail("%s: tls must be starttls, implicit or none", where)
		}
		if (e.Username == "") != (e.Password == "") {
			fail("%s: set both username and password, or neither", where)
		}
		if _, err := mail.ParseAddress(e.From); err != nil {
			fail("%s: from %q is not a valid address", where, e.From)
		}
		if len(e.To) == 0 {
			fail("%s: at least one recipient in to is required", where)
		}
		for _, to := range e.To {
			if _, err := mail.ParseAddress(to); err != nil {
				fail("%s: recipient %q is not a valid address", where, to)
			}
		}
		checkEvents(where, e.Events)
	}
}

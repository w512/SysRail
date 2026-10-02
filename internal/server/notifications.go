package server

import (
	"os"

	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/notify"
)

// Hostname names this machine in notifications.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "localhost"
	}
	return h
}

// NotificationChannels builds the channels configured in cfg.
func NotificationChannels(cfg *config.Config, host string) []notify.Channel {
	n := cfg.Notifications
	var out []notify.Channel
	for _, w := range n.Webhooks {
		out = append(out, notify.NewWebhook(w.URL, w.Headers, w.Events))
	}
	for _, c := range n.Ntfy {
		out = append(out, notify.NewNtfy(c.URL, c.Token, c.Events))
	}
	for _, t := range n.Telegram {
		out = append(out, notify.NewTelegram(t.BotToken, t.ChatID, t.APIURL, t.Events))
	}
	for _, e := range n.Email {
		out = append(out, notify.NewEmail(notify.EmailConfig{
			Host: e.SMTPHost, Port: e.SMTPPort, TLS: e.TLS, Username: e.Username, Password: e.Password,
			From: e.From, To: e.To, Events: e.Events, HelloName: host,
		}))
	}
	return out
}

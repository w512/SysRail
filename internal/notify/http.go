package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/w512/SysRail/internal/version"
)

var httpClient = &http.Client{
	// Redirects could forward credentials headers to another host.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// post sends body and classifies the outcome for retries.
func post(ctx context.Context, target, contentType string, body []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, permanent(cleanErr(err))
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "sysrail/"+version.Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, retryable(cleanErr(err))
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}
	err = fmt.Errorf("HTTP %d: %s", resp.StatusCode, excerpt(respBody))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return respBody, retryable(err)
	}
	return respBody, permanent(err)
}

func excerpt(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// displayURL shows scheme, host and path only: no credentials or query.
func displayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(invalid URL)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// Webhook posts the message as JSON.
type Webhook struct {
	subscription
	url     string
	headers map[string]string
}

// NewWebhook returns a webhook channel.
func NewWebhook(target string, headers map[string]string, eventTypes []string) *Webhook {
	return &Webhook{subscription: newSubscription(eventTypes), url: target, headers: headers}
}

func (w *Webhook) Name() string { return "webhook " + displayURL(w.url) }

func (w *Webhook) Send(ctx context.Context, m *Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return permanent(err)
	}
	_, err = post(ctx, w.url, "application/json", body, w.headers)
	return err
}

// Ntfy publishes the message to an ntfy topic.
type Ntfy struct {
	subscription
	url   string
	token string
}

// NewNtfy returns an ntfy channel for a topic URL such as
// https://ntfy.sh/my-topic.
func NewNtfy(topicURL, token string, eventTypes []string) *Ntfy {
	return &Ntfy{subscription: newSubscription(eventTypes), url: topicURL, token: token}
}

func (n *Ntfy) Name() string { return "ntfy " + displayURL(n.url) }

func (n *Ntfy) Send(ctx context.Context, m *Message) error {
	headers := map[string]string{"Title": m.Title, "Priority": m.Priority, "Tags": ntfyTags(m.Type)}
	if n.token != "" {
		headers["Authorization"] = "Bearer " + n.token
	}
	_, err := post(ctx, n.url, "text/plain; charset=utf-8", []byte(m.Text), headers)
	return err
}

func ntfyTags(eventType string) string {
	switch eventType {
	case "request.pending":
		return "raising_hand"
	case "request.executed", "service.recovered":
		return "white_check_mark"
	case "request.failed", "request.denied", "service.failed":
		return "rotating_light"
	case "request.expired":
		return "hourglass"
	}
	return "information_source"
}

// Telegram sends the message through a Telegram bot.
type Telegram struct {
	subscription
	api    string
	token  string
	chatID string
}

// NewTelegram returns a Telegram channel. apiURL defaults to
// https://api.telegram.org.
func NewTelegram(botToken, chatID, apiURL string, eventTypes []string) *Telegram {
	if apiURL == "" {
		apiURL = "https://api.telegram.org"
	}
	return &Telegram{subscription: newSubscription(eventTypes), api: strings.TrimSuffix(apiURL, "/"),
		token: botToken, chatID: chatID}
}

func (t *Telegram) Name() string { return "telegram chat " + t.chatID }

// telegramLimit is the maximum message length accepted by the Bot API.
const telegramLimit = 4096

func (t *Telegram) Send(ctx context.Context, m *Message) error {
	text := m.Title + "\n\n" + m.Text
	if utf8.RuneCountInString(text) > telegramLimit {
		text = string([]rune(text)[:telegramLimit-1]) + "…"
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id":              t.chatID,
		"text":                 text,
		"link_preview_options": map[string]bool{"is_disabled": true},
	})
	resp, err := post(ctx, t.api+"/bot"+t.token+"/sendMessage", "application/json", body, nil)
	if err != nil {
		var se *SendError
		if errors.As(err, &se) && resp != nil {
			var apiErr struct {
				Description string `json:"description"`
			}
			if json.Unmarshal(resp, &apiErr) == nil && apiErr.Description != "" {
				return &SendError{Err: errors.New("telegram: " + apiErr.Description), Retryable: se.Retryable}
			}
		}
		return err
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(resp, &ok) != nil || !ok.OK {
		return permanent(fmt.Errorf("telegram: unexpected response: %s", excerpt(resp)))
	}
	return nil
}

package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/core/redact"
	"github.com/w512/SysRail/internal/core/request"
)

// Message is a rendered notification.
type Message struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Text     string       `json:"text"`
	Priority string       `json:"priority"` // "high" or "default"
	Host     string       `json:"host"`
	Event    events.Event `json:"event"`
	Request  *RequestInfo `json:"request,omitempty"`
}

// RequestInfo describes the request behind a request event.
type RequestInfo struct {
	ID           string     `json:"request_id"`
	Agent        string     `json:"agent"`
	Capability   string     `json:"capability"`
	Resource     string     `json:"resource,omitempty"`
	Risk         string     `json:"risk,omitempty"`
	Status       string     `json:"status"`
	Reason       string     `json:"reason,omitempty"`
	Impact       string     `json:"impact,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`
	ErrorCode    string     `json:"error_code,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// Build renders an event as a message.
func (n *Notifier) Build(ctx context.Context, e events.Event) *Message {
	m := &Message{Type: e.Type, Host: n.o.Host, Event: e, Priority: "default"}
	if strings.HasPrefix(e.Type, "request.") {
		m.Request = n.requestInfo(ctx, e)
	}
	r := m.Request
	switch e.Type {
	case events.RequestPending:
		m.Priority = "high"
		m.Title = "SysRail: approval needed on " + n.o.Host
		var b strings.Builder
		fmt.Fprintf(&b, "%s requests %s", r.Agent, r.Capability)
		if r.Resource != "" {
			fmt.Fprintf(&b, " on %s", r.Resource)
		}
		if r.Risk != "" {
			fmt.Fprintf(&b, " (risk: %s)", r.Risk)
		}
		b.WriteString(".\n")
		if r.Impact != "" {
			fmt.Fprintf(&b, "Impact: %s\n", r.Impact)
		}
		if r.Reason != "" {
			fmt.Fprintf(&b, "Reason (from the agent, unverified): %s\n", r.Reason)
		}
		if r.ExpiresAt != nil {
			fmt.Fprintf(&b, "Expires: %s\n", r.ExpiresAt.Local().Format("2006-01-02 15:04:05 MST"))
		}
		fmt.Fprintf(&b, "\nApprove: sudo sysrail approvals approve %s\nDeny:    sudo sysrail approvals deny %s", r.ID, r.ID)
		m.Text = b.String()
	case events.RequestApproved, events.RequestDenied, events.RequestExpired, events.RequestExecuted, events.RequestFailed:
		status := strings.TrimPrefix(e.Type, "request.")
		if status == "failed" || status == "denied" {
			m.Priority = "high"
		}
		m.Title = fmt.Sprintf("SysRail: request %s on %s", status, n.o.Host)
		target := r.Capability
		if r.Resource != "" {
			target += " on " + r.Resource
		}
		text := fmt.Sprintf("%s for %s (%s) was %s", target, r.Agent, r.ID, status)
		if r.DecidedBy != "" && (status == "approved" || status == "denied") {
			text += " by " + r.DecidedBy
		}
		text += "."
		if r.DecisionNote != "" {
			text += "\nNote: " + r.DecisionNote
		}
		if r.ErrorCode != "" {
			text += fmt.Sprintf("\nError: %s: %s", r.ErrorCode, r.ErrorMessage)
		}
		m.Text = text
	case events.ServiceFailed:
		m.Priority = "high"
		m.Title = fmt.Sprintf("SysRail: %s failed on %s", e.Resource, n.o.Host)
		m.Text = fmt.Sprintf("%s entered the failed state%s.", e.Resource, stateDetail(e))
	case events.ServiceRecovered:
		m.Title = fmt.Sprintf("SysRail: %s recovered on %s", e.Resource, n.o.Host)
		m.Text = fmt.Sprintf("%s is active again%s.", e.Resource, stateDetail(e))
	default:
		m.Title = fmt.Sprintf("SysRail: %s on %s", e.Type, n.o.Host)
		m.Text = fmt.Sprintf("%s %s", e.Type, e.Resource)
	}
	return m
}

func stateDetail(e events.Event) string {
	var parts []string
	if s, _ := e.Data["sub_state"].(string); s != "" {
		parts = append(parts, "sub-state: "+s)
	}
	if s, _ := e.Data["previous_state"].(string); s != "" {
		parts = append(parts, "previously "+s)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func (n *Notifier) requestInfo(ctx context.Context, e events.Event) *RequestInfo {
	id, _ := e.Data["request_id"].(string)
	info := &RequestInfo{ID: id, Agent: e.Agent, Resource: e.Resource}
	info.Capability, _ = e.Data["capability"].(string)
	info.Status, _ = e.Data["status"].(string)
	var r *request.Request
	if n.o.Lookup != nil && id != "" {
		r, _ = n.o.Lookup(ctx, id)
	}
	if r != nil {
		info.Agent, info.Capability, info.Resource = r.Agent, r.Capability, r.Resource
		info.Risk, info.ExpiresAt = string(r.Risk), r.ExpiresAt
		info.Reason = untrusted(r.Reason)
		info.DecidedBy, info.DecisionNote = r.DecidedBy, untrusted(r.DecisionNote)
		if r.Error != nil {
			info.ErrorCode, info.ErrorMessage = string(r.Error.Code), r.Error.Message
		}
	}
	if n.o.Impact != nil && info.Capability != "" {
		info.Impact = n.o.Impact(info.Capability)
	}
	return info
}

// untrusted cleans free text before it reaches a human: control characters
// become spaces, secrets are masked and length is bounded.
func untrusted(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = redact.String(strings.TrimSpace(s))
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return s
}

func (n *Notifier) testMessage() *Message {
	e := events.Event{Type: "test", Source: "core", Time: time.Now().UTC()}
	return &Message{
		Type: "test", Priority: "default", Host: n.o.Host, Event: e,
		Title: "SysRail: test notification from " + n.o.Host,
		Text: "This is a test notification from SysRail on " + n.o.Host + ".\n" +
			"Requests that need approval will be announced here.",
	}
}

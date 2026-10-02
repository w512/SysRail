// Package notify sends notifications about daemon events (above all, requests
// waiting for approval) to webhooks, ntfy, Telegram and email. Delivery runs
// in the background with retries and never slows down request handling.
package notify

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/core/request"
)

// DefaultEvents are sent when a channel does not list events.
var DefaultEvents = []string{events.RequestPending}

// Channel delivers messages to one destination.
type Channel interface {
	// Name identifies the channel in logs without revealing secrets.
	Name() string
	// Wants reports whether the channel subscribes to an event type.
	Wants(eventType string) bool
	// Send delivers one message. Errors wrapped in *SendError tell the
	// dispatcher whether to retry.
	Send(ctx context.Context, m *Message) error
}

// SendError marks whether a failed delivery may succeed when retried.
type SendError struct {
	Err       error
	Retryable bool
}

func (e *SendError) Error() string { return e.Err.Error() }
func (e *SendError) Unwrap() error { return e.Err }

func retryable(err error) error  { return &SendError{Err: err, Retryable: true} }
func permanent(err error) error  { return &SendError{Err: err, Retryable: false} }
func isRetryable(err error) bool { var se *SendError; return !errors.As(err, &se) || se.Retryable }

// cleanErr strips the request URL from HTTP client errors: URLs can carry
// secrets such as a Telegram bot token.
func cleanErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

type subscription struct{ types []string }

func (s subscription) Wants(t string) bool { return slices.Contains(s.types, t) }

func newSubscription(types []string) subscription {
	if len(types) == 0 {
		types = DefaultEvents
	}
	return subscription{types: types}
}

// Options configures a Notifier.
type Options struct {
	Channels []Channel
	// Host names the machine in messages.
	Host string
	// Lookup loads a request to enrich request events. Optional.
	Lookup func(ctx context.Context, id string) (*request.Request, error)
	// Impact returns the trusted impact text of a capability. Optional.
	Impact func(capability string) string
	Log    *slog.Logger
	// Retry is the wait before each retry. Default: 2s, 10s, 30s.
	Retry []time.Duration
	// Timeout bounds one delivery attempt. Default 15s.
	Timeout time.Duration
}

// Notifier turns events into messages and delivers them.
type Notifier struct {
	o Options
}

// New returns a notifier.
func New(o Options) *Notifier {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Retry == nil {
		o.Retry = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	return &Notifier{o: o}
}

// Channels returns the configured channels.
func (n *Notifier) Channels() []Channel { return n.o.Channels }

// Run delivers events from bus until ctx is canceled. Each channel has its
// own queue, so a slow or failing destination does not delay the others.
func (n *Notifier) Run(ctx context.Context, bus *events.Bus) {
	if len(n.o.Channels) == 0 {
		return
	}
	queues := make([]chan *Message, len(n.o.Channels))
	var wg sync.WaitGroup
	for i, c := range n.o.Channels {
		queues[i] = make(chan *Message, 100)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range queues[i] {
				n.deliver(ctx, c, m)
			}
		}()
	}
	_, ch, cancel := bus.Subscribe(0, func(e events.Event) bool {
		for _, c := range n.o.Channels {
			if c.Wants(e.Type) {
				return true
			}
		}
		return false
	})
	defer func() {
		cancel()
		for _, q := range queues {
			close(q)
		}
		wg.Wait()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			m := n.Build(ctx, e)
			for i, c := range n.o.Channels {
				if !c.Wants(e.Type) {
					continue
				}
				select {
				case queues[i] <- m:
				default:
					n.o.Log.Warn("notification queue full; dropping message", "channel", c.Name(), "event", e.Type)
				}
			}
		}
	}
}

func (n *Notifier) deliver(ctx context.Context, c Channel, m *Message) {
	for attempt := 0; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, n.o.Timeout)
		err := c.Send(actx, m)
		cancel()
		if err == nil {
			n.o.Log.Debug("notification sent", "channel", c.Name(), "event", m.Type)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if !isRetryable(err) || attempt >= len(n.o.Retry) {
			n.o.Log.Warn("notification failed", "channel", c.Name(), "event", m.Type,
				"attempts", attempt+1, "error", cleanErr(err).Error())
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(n.o.Retry[attempt]):
		}
	}
}

// TestResult is the outcome of sending a test message to one channel.
type TestResult struct {
	Channel string
	Err     error
}

// Test sends a test message to every channel once, without retries.
func (n *Notifier) Test(ctx context.Context) []TestResult {
	m := n.testMessage()
	out := make([]TestResult, 0, len(n.o.Channels))
	for _, c := range n.o.Channels {
		actx, cancel := context.WithTimeout(ctx, n.o.Timeout)
		err := c.Send(actx, m)
		cancel()
		if err != nil {
			err = cleanErr(err)
		}
		out = append(out, TestResult{Channel: c.Name(), Err: err})
	}
	return out
}

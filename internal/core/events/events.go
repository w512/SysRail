// Package events is an in-memory event bus (spec §20). Recent events are
// kept in a ring buffer so reconnecting subscribers can resume by ID.
package events

import (
	"sync"
	"time"
)

// Event types.
const (
	RequestPending   = "request.pending"
	RequestApproved  = "request.approved"
	RequestDenied    = "request.denied"
	RequestExpired   = "request.expired"
	RequestExecuted  = "request.executed"
	RequestFailed    = "request.failed"
	ServiceFailed    = "service.failed"
	ServiceRecovered = "service.recovered"
)

// Types lists every event type the daemon emits.
var Types = []string{
	RequestPending, RequestApproved, RequestDenied, RequestExpired, RequestExecuted, RequestFailed,
	ServiceFailed, ServiceRecovered,
}

// Event is something that happened.
type Event struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	Source string    `json:"source"`
	// Agent owns the event (request events); empty for host events.
	Agent string `json:"agent,omitempty"`
	// ResourceKind and Resource identify what the event is about.
	ResourceKind string         `json:"resource_kind,omitempty"`
	Resource     string         `json:"resource,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
}

type subscriber struct {
	ch     chan Event
	filter func(Event) bool
}

// Bus fans events out to subscribers. Slow subscribers miss events rather
// than blocking publishers.
type Bus struct {
	mu      sync.Mutex
	seq     int64
	history []Event
	size    int
	subs    map[*subscriber]struct{}
}

// NewBus returns a bus remembering the last history events.
func NewBus(history int) *Bus {
	if history <= 0 {
		history = 256
	}
	return &Bus{size: history, subs: map[*subscriber]struct{}{}}
}

// Publish assigns an ID and timestamp and delivers e. A nil bus is a no-op.
func (b *Bus) Publish(e Event) Event {
	if b == nil {
		return e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	e.ID = b.seq
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b.history = append(b.history, e)
	if len(b.history) > b.size {
		b.history = b.history[len(b.history)-b.size:]
	}
	for s := range b.subs {
		if s.filter != nil && !s.filter(e) {
			continue
		}
		select {
		case s.ch <- e:
		default:
		}
	}
	return e
}

// Subscribe returns buffered events after the given ID that pass filter,
// followed by a channel of new ones. Call cancel when done.
func (b *Bus) Subscribe(after int64, filter func(Event) bool) ([]Event, <-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var replay []Event
	for _, e := range b.history {
		if e.ID > after && (filter == nil || filter(e)) {
			replay = append(replay, e)
		}
	}
	s := &subscriber{ch: make(chan Event, 64), filter: filter}
	b.subs[s] = struct{}{}
	var once sync.Once
	return replay, s.ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, s)
			b.mu.Unlock()
		})
	}
}

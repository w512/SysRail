package systemd

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/providers"
)

var _ providers.EventSource = (*Provider)(nil)

func TestWatchEmitsTransitions(t *testing.T) {
	m := newFakeManager()
	p := New(Options{Manager: m, WatchInterval: 10 * time.Millisecond})
	var mu sync.Mutex
	var got []events.Event
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Watch(ctx, func(e events.Event) {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
		})
		close(done)
	}()
	set := func(unit, state string) {
		m.mu.Lock()
		m.units[unit].ActiveState = state
		m.mu.Unlock()
	}
	wait := func(n int) []events.Event {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			if len(got) >= n {
				out := append([]events.Event(nil), got...)
				mu.Unlock()
				return out
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %d events, have %+v", n, got)
		return nil
	}

	time.Sleep(30 * time.Millisecond) // baseline: nginx is already failed, no event
	set("cron.service", "failed")
	wait(1)
	set("cron.service", "active")
	set("nginx.service", "active")
	evs := wait(3)
	cancel()
	<-done

	if evs[0].Type != events.ServiceFailed || evs[0].Resource != "cron.service" || evs[0].Data["previous_state"] != "active" {
		t.Fatalf("first event: %+v", evs[0])
	}
	recovered := map[string]bool{}
	for _, e := range evs[1:] {
		if e.Type != events.ServiceRecovered || e.ResourceKind != "service" || e.Source != "systemd" {
			t.Fatalf("event: %+v", e)
		}
		recovered[e.Resource] = true
	}
	if !recovered["cron.service"] || !recovered["nginx.service"] {
		t.Fatalf("recoveries: %v", recovered)
	}
	if len(got) != 3 {
		t.Fatalf("unexpected extra events: %+v", got)
	}
}

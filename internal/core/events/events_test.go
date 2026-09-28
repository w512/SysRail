package events

import (
	"testing"
	"time"
)

func TestPublishSubscribeAndReplay(t *testing.T) {
	b := NewBus(3)
	for _, typ := range []string{"a", "b", "c", "d"} {
		b.Publish(Event{Type: typ})
	}
	replay, ch, cancel := b.Subscribe(2, func(e Event) bool { return e.Type != "c" })
	defer cancel()
	if len(replay) != 1 || replay[0].Type != "d" || replay[0].ID != 4 {
		t.Fatalf("replay (history 3, after 2, without c): %+v", replay)
	}
	b.Publish(Event{Type: "c"})
	b.Publish(Event{Type: "e"})
	select {
	case e := <-ch:
		if e.Type != "e" || e.ID != 6 || e.Time.IsZero() {
			t.Fatalf("got %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event delivered")
	}
	cancel()
	cancel()
	b.Publish(Event{Type: "f"})
	select {
	case e := <-ch:
		t.Fatalf("delivered after cancel: %+v", e)
	default:
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	b := NewBus(10)
	_, _, cancel := b.Subscribe(0, nil)
	defer cancel()
	done := make(chan struct{})
	go func() {
		for range 500 {
			b.Publish(Event{Type: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher blocked on a slow subscriber")
	}
}

func TestNilBus(t *testing.T) {
	var b *Bus
	b.Publish(Event{Type: "x"})
}

package core

import (
	"strings"
	"testing"
)

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	prev := ""
	for range 1000 {
		id := NewID("req")
		if !strings.HasPrefix(id, "req_") || len(id) != 30 {
			t.Fatalf("bad id %q", id)
		}
		for _, c := range id[4:] {
			if !strings.ContainsRune(crockford, c) {
				t.Fatalf("bad character %q in %q", c, id)
			}
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
		if id[4:14] < prev {
			t.Fatalf("timestamp prefix went backwards: %q < %q", id[4:14], prev)
		}
		prev = id[4:14]
	}
}

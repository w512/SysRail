package auth

import (
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, TokenPrefix) || len(tok) < 40 || !ValidHash(hash) || Hash(tok) != hash {
		t.Fatalf("token %q hash %q", tok, hash)
	}
	other, otherHash, _ := NewToken()
	a, err := NewAuthenticator(map[string]string{"opencode": hash, "blue": otherHash})
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := a.Agent(tok); !ok || name != "opencode" {
		t.Fatalf("got %q %v", name, ok)
	}
	if name, ok := a.Agent(other); !ok || name != "blue" {
		t.Fatalf("got %q %v", name, ok)
	}
	for _, bad := range []string{"", "sysrail_nope", hash} {
		if _, ok := a.Agent(bad); ok {
			t.Fatalf("token %q accepted", bad)
		}
	}
}

func TestAuthenticatorValidation(t *testing.T) {
	if _, err := NewAuthenticator(map[string]string{"a": "short"}); err == nil {
		t.Fatal("bad hash accepted")
	}
	h := Hash("x")
	if _, err := NewAuthenticator(map[string]string{"a": h, "b": h}); err == nil {
		t.Fatal("shared token accepted")
	}
	if _, err := NewAuthenticator(map[string]string{"a": strings.ToUpper(h)}); err == nil {
		t.Fatal("uppercase hash accepted")
	}
}

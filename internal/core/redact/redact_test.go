package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		in, secret string
	}{
		{"DB_PASSWORD=hunter22 started", "hunter22"},
		{"password: hunter22", "hunter22"},
		{`{"api_key": "abc123xyz"}`, "abc123xyz"},
		{"export GITHUB_TOKEN='ghx-secret-value'", "ghx-secret-value"},
		{"Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"},
		{"connecting to postgres://app:s3cr3tpw@db:5432/app", "s3cr3tpw"},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpM", "SflKxwRJSMeKKF2QT4fwpM"},
		{"key ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"aws AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----", "MIIEpAIBAAKCAQEA"},
		{"truncated -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk", "b3BlbnNzaC1rZXk"},
		{"client_secret=xyz789&grant=1", "xyz789"},
	}
	for _, tt := range tests {
		got := String(tt.in)
		if strings.Contains(got, tt.secret) {
			t.Errorf("String(%q) = %q, still contains secret", tt.in, got)
		}
		if !strings.Contains(got, Mask) {
			t.Errorf("String(%q) = %q, missing mask", tt.in, got)
		}
		if again := String(got); again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
}

func TestStringKeepsOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"nginx.service: Main process exited, code=exited, status=1/FAILURE",
		"Started Session 3 of User sky.",
		"listening on 0.0.0.0:8080",
		"idempotency_key=abc",
	} {
		if got := String(s); got != s {
			t.Errorf("String(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestValue(t *testing.T) {
	in := map[string]any{
		"name":     "nginx",
		"password": "hunter22",
		"env":      []any{"HOME=/root", "API_TOKEN=abc123"},
		"nested":   map[string]any{"client_secret": map[string]any{"x": 1}, "count": 3.0},
		"empty":    map[string]any{"token": ""},
	}
	out, _ := json.Marshal(Value(in))
	s := string(out)
	for _, secret := range []string{"hunter22", "abc123", `"x"`} {
		if strings.Contains(s, secret) {
			t.Errorf("redacted value still contains %s: %s", secret, s)
		}
	}
	for _, keep := range []string{`"name":"nginx"`, "HOME=/root", `"count":3`, `"token":""`} {
		if !strings.Contains(s, keep) {
			t.Errorf("redacted value lost %s: %s", keep, s)
		}
	}
}

func TestJSON(t *testing.T) {
	if got := string(JSON(json.RawMessage(`{"token":"abc"}`))); got != `{"token":"[REDACTED]"}` {
		t.Fatalf("got %s", got)
	}
	if got := string(JSON(json.RawMessage(`not json password=abc`))); strings.Contains(got, "abc") {
		t.Fatalf("got %s", got)
	}
	if got := JSON(nil); got != nil {
		t.Fatalf("got %s", got)
	}
}

func FuzzString(f *testing.F) {
	f.Add("password=abc")
	f.Add("Bearer abcdefghijkl")
	f.Add("-----BEGIN PRIVATE KEY-----")
	f.Add("https://u:p@h/")
	f.Fuzz(func(t *testing.T, s string) {
		got := String(s)
		if again := String(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, got, again)
		}
		const secret = "Zq9SuperSecretValue"
		if out := String(s + " password=" + secret); strings.Contains(out, secret) {
			t.Fatalf("secret leaked: %q", out)
		}
	})
}

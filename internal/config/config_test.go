package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/auth"
)

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAppliesDefaultsAndResolvesPaths(t *testing.T) {
	hash := auth.Hash("tok")
	path := write(t, `
database: state/sysrail.db
policy_file: policy.yaml
server:
  admin_socket: run/admin.sock
  agent_socket: ""
agents:
  opencode:
    token_sha256: `+hash+`
providers:
  systemd:
    enabled: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if cfg.Database != filepath.Join(dir, "state/sysrail.db") || cfg.PolicyFile != filepath.Join(dir, "policy.yaml") ||
		cfg.Server.AdminSocket != filepath.Join(dir, "run/admin.sock") {
		t.Fatalf("paths not resolved: %+v", cfg)
	}
	if cfg.Server.HTTPListen != "127.0.0.1:9487" || cfg.Approvals.TTL != 15*time.Minute ||
		cfg.Timeouts.Read != 10*time.Second || !cfg.Providers.Linux.Enabled || cfg.Providers.Systemd.Enabled {
		t.Fatalf("defaults: %+v", cfg)
	}
	if cfg.AgentHashes()["opencode"] != hash || !cfg.AgentNames()["opencode"] {
		t.Fatal("agents not loaded")
	}
	if cfg.Audit.RetentionDays != 90 || cfg.ArchiveDirectory() != filepath.Join(dir, "state", "archive") {
		t.Fatalf("audit defaults: %+v %q", cfg.Audit, cfg.ArchiveDirectory())
	}
}

func TestValidation(t *testing.T) {
	h := auth.Hash("a")
	tests := []struct{ name, body, want string }{
		{"unknown field", "databse: x\n", "field databse not found"},
		{"remote bind", "server:\n  http_listen: 0.0.0.0:9487\n", "not a loopback"},
		{"bad listen", "server:\n  http_listen: nope\n", "http_listen"},
		{"no listeners", "server:\n  http_listen: \"\"\n  agent_socket: \"\"\n", "at least one"},
		{"same sockets", "server:\n  agent_socket: /tmp/s\n  admin_socket: /tmp/s\n", "must differ"},
		{"ttl", "approvals:\n  ttl: 10s\n", "approvals.ttl"},
		{"timeout", "timeouts:\n  read: 1h\n", "timeouts.read"},
		{"agent name", "agents:\n  Bad Name:\n    token_sha256: " + h + "\n", "invalid agent name"},
		{"agent hash", "agents:\n  a:\n    token_sha256: xyz\n", "64 lowercase hex"},
		{"admin reuse", "admin:\n  token_sha256: " + h + "\nagents:\n  a:\n    token_sha256: " + h + "\n", "reuse the admin token"},
		{"log level", "log:\n  level: loud\n", "log.level"},
		{"retention", "audit:\n  retention_days: -1\n", "audit.retention_days"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestRelativeConfigPathYieldsAbsolutePaths(t *testing.T) {
	path := write(t, "database: sysrail.db\n")
	t.Chdir(filepath.Dir(path))
	cfg, err := Load("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.Database) {
		t.Fatalf("database path %q is relative", cfg.Database)
	}
}

func TestArchiveSettings(t *testing.T) {
	path := write(t, "audit:\n  archive_dir: old-audit\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ArchiveDirectory() != filepath.Join(filepath.Dir(path), "old-audit") {
		t.Fatalf("archive dir: %q", cfg.ArchiveDirectory())
	}
	cfg.Audit.Archive = false
	if cfg.ArchiveDirectory() != "" {
		t.Fatal("disabled archiving must return an empty directory")
	}
}

func TestRemoteBindCanBeAllowed(t *testing.T) {
	if _, err := Load(write(t, "server:\n  http_listen: 0.0.0.0:9487\n  allow_remote: true\n")); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationsConfig(t *testing.T) {
	cfg, err := Load(write(t, `
notifications:
  webhooks:
    - url: https://hooks.example.com/sysrail
      headers: {Authorization: "Bearer x"}
  ntfy:
    - url: https://ntfy.sh/my-sysrail
      events: [request.pending, service.failed]
  telegram:
    - bot_token: "123456:ABC-def"
      chat_id: -1001234567890
  email:
    - smtp_host: smtp.example.com
      username: bot
      password: secret
      from: SysRail <sysrail@example.com>
      to: [ops@example.com]
`))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.Notifications
	if n.Count() != 4 || n.Telegram[0].ChatID != "-1001234567890" || n.Ntfy[0].Events[1] != "service.failed" {
		t.Fatalf("notifications: %+v", n)
	}
}

func TestNotificationsValidation(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"webhook url", "notifications:\n  webhooks:\n    - url: ftp://x\n", "absolute http(s) URL"},
		{"ntfy topic", "notifications:\n  ntfy:\n    - url: https://ntfy.sh/\n", "must include the topic"},
		{"event", "notifications:\n  webhooks:\n    - url: https://x\n      events: [request.pendng]\n", "unknown event"},
		{"telegram token", "notifications:\n  telegram:\n    - chat_id: \"1\"\n", "bot_token is required"},
		{"telegram chat", "notifications:\n  telegram:\n    - bot_token: \"1:a\"\n", "chat_id is required"},
		{"email tls", "notifications:\n  email:\n    - smtp_host: h\n      tls: ssl\n      from: a@b.c\n      to: [d@e.f]\n", "tls must be"},
		{"email plaintext password", "notifications:\n  email:\n    - smtp_host: h\n      tls: none\n      username: u\n      password: p\n      from: a@b.c\n      to: [d@e.f]\n", "unencrypted"},
		{"email half credentials", "notifications:\n  email:\n    - smtp_host: h\n      username: u\n      from: a@b.c\n      to: [d@e.f]\n", "both username and password"},
		{"email from", "notifications:\n  email:\n    - smtp_host: h\n      from: nope\n      to: [d@e.f]\n", "not a valid address"},
		{"email to", "notifications:\n  email:\n    - smtp_host: h\n      from: a@b.c\n", "at least one recipient"},
		{"unknown key", "notifications:\n  slack:\n    - url: https://x\n", "field slack not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want error containing %q", err, tt.want)
			}
		})
	}
}

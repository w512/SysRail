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

func TestRemoteBindCanBeAllowed(t *testing.T) {
	if _, err := Load(write(t, "server:\n  http_listen: 0.0.0.0:9487\n  allow_remote: true\n")); err != nil {
		t.Fatal(err)
	}
}

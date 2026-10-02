// Package config loads the daemon configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/w512/SysRail/internal/auth"
)

// DefaultPath is where the daemon looks for its configuration.
const DefaultPath = "/etc/sysrail/config.yaml"

// Config is the daemon configuration.
type Config struct {
	Server     Server           `yaml:"server"`
	Database   string           `yaml:"database"`
	PolicyFile string           `yaml:"policy_file"`
	Approvals  Approvals        `yaml:"approvals"`
	Audit      Audit            `yaml:"audit"`
	Limits     Limits           `yaml:"limits"`
	Timeouts   Timeouts         `yaml:"timeouts"`
	Admin      Admin            `yaml:"admin"`
	Agents     map[string]Agent `yaml:"agents"`
	Providers  Providers        `yaml:"providers"`
	// Notifications are sent from the daemon; secrets here are why the
	// config file must stay readable only by root and the sysrail group.
	Notifications Notifications `yaml:"notifications"`
	Log           Log           `yaml:"log"`
}

// Server configures listeners.
type Server struct {
	// HTTPListen is a TCP address for the HTTP API; empty disables it.
	HTTPListen string `yaml:"http_listen"`
	// AllowRemote must be true to bind HTTPListen to a non-loopback address.
	AllowRemote bool `yaml:"allow_remote"`
	// AgentSocket is a Unix socket serving the agent API; empty disables it.
	AgentSocket string `yaml:"agent_socket"`
	// AgentSocketGroup, if set, owns the agent socket (mode 0660).
	AgentSocketGroup string `yaml:"agent_socket_group"`
	// AdminSocket is a Unix socket (mode 0600) serving the admin API.
	AdminSocket string `yaml:"admin_socket"`
}

// Approvals configures the approval flow.
type Approvals struct {
	TTL time.Duration `yaml:"ttl"`
}

// Audit configures audit log retention.
type Audit struct {
	// RetentionDays keeps audit records and finished requests this many
	// days; 0 keeps them forever.
	RetentionDays int `yaml:"retention_days"`
	// Archive writes removed records to ArchiveDir as .jsonl.gz files.
	Archive bool `yaml:"archive"`
	// ArchiveDir defaults to an "archive" directory next to the database.
	ArchiveDir string `yaml:"archive_dir"`
}

// ArchiveDirectory returns where retention writes archives, or "" when
// archiving is disabled.
func (c *Config) ArchiveDirectory() string {
	if !c.Audit.Archive {
		return ""
	}
	if c.Audit.ArchiveDir != "" {
		return c.Audit.ArchiveDir
	}
	return filepath.Join(filepath.Dir(c.Database), "archive")
}

// Timeouts are default capability timeouts.
type Timeouts struct {
	Read     time.Duration `yaml:"read"`
	Mutating time.Duration `yaml:"mutating"`
}

// Admin configures admin access over TCP.
type Admin struct {
	// TokenSHA256 enables the admin API on the TCP listener for holders of
	// the matching token. Leave empty to restrict admin to the admin socket.
	TokenSHA256 string `yaml:"token_sha256"`
}

// Agent is an agent identity.
type Agent struct {
	TokenSHA256 string `yaml:"token_sha256"`
	// Limits overrides the global limits for this agent.
	Limits *AgentLimits `yaml:"limits"`
}

// Limits bound each agent. Zero disables a limit.
type Limits struct {
	// CallsPerMinute is the sustained rate of calls across all tools.
	CallsPerMinute int `yaml:"calls_per_minute"`
	// Burst is how many calls may be made back to back.
	Burst int `yaml:"burst"`
	// MaxPending caps requests waiting for approval at the same time.
	MaxPending int `yaml:"max_pending"`
}

// AgentLimits overrides individual global limits; unset fields inherit.
type AgentLimits struct {
	CallsPerMinute *int `yaml:"calls_per_minute"`
	Burst          *int `yaml:"burst"`
	MaxPending     *int `yaml:"max_pending"`
}

// LimitsFor returns the effective limits for an agent.
func (c *Config) LimitsFor(agent string) Limits {
	l := c.Limits
	if a, ok := c.Agents[agent]; ok && a.Limits != nil {
		if a.Limits.CallsPerMinute != nil {
			l.CallsPerMinute = *a.Limits.CallsPerMinute
		}
		if a.Limits.Burst != nil {
			l.Burst = *a.Limits.Burst
		}
		if a.Limits.MaxPending != nil {
			l.MaxPending = *a.Limits.MaxPending
		}
	}
	return l
}

func (l Limits) validate(where string, fail func(string, ...any)) {
	switch {
	case l.CallsPerMinute < 0 || l.CallsPerMinute > 100000:
		fail("%s.calls_per_minute must be between 0 (unlimited) and 100000", where)
	case l.Burst < 0 || l.Burst > 10000:
		fail("%s.burst must be between 0 and 10000", where)
	case l.CallsPerMinute > 0 && l.Burst < 1:
		fail("%s.burst must be at least 1 when calls_per_minute is set", where)
	case l.MaxPending < 0 || l.MaxPending > 10000:
		fail("%s.max_pending must be between 0 (unlimited) and 10000", where)
	}
}

// Providers enables and configures providers.
type Providers struct {
	Linux   Linux   `yaml:"linux"`
	Systemd Systemd `yaml:"systemd"`
}

// Linux configures the generic Linux provider.
type Linux struct {
	Enabled bool `yaml:"enabled"`
}

// Systemd configures the systemd provider.
type Systemd struct {
	Enabled bool `yaml:"enabled"`
	// ProtectedUnits replaces the default list of units that may never be
	// started, stopped or restarted. sysrail.service is always protected.
	ProtectedUnits []string `yaml:"protected_units"`
}

// Log configures logging.
type Log struct {
	Level string `yaml:"level"`
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		Server: Server{
			HTTPListen:  "127.0.0.1:9487",
			AgentSocket: "/run/sysrail/agent.sock",
			AdminSocket: "/run/sysrail/admin.sock",
		},
		Database:   "/var/lib/sysrail/sysrail.db",
		PolicyFile: "/etc/sysrail/policy.yaml",
		Approvals:  Approvals{TTL: 15 * time.Minute},
		Audit:      Audit{RetentionDays: 90, Archive: true},
		Limits:     Limits{CallsPerMinute: 120, Burst: 30, MaxPending: 10},
		Timeouts:   Timeouts{Read: 10 * time.Second, Mutating: 60 * time.Second},
		Providers:  Providers{Linux: Linux{Enabled: true}, Systemd: Systemd{Enabled: true}},
		Log:        Log{Level: "info"},
	}
}

// Load reads, validates and resolves the configuration at path. Relative
// paths inside it are resolved against the file's directory.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	base := filepath.Dir(abs)
	for _, p := range []*string{&cfg.Database, &cfg.PolicyFile, &cfg.Server.AgentSocket, &cfg.Server.AdminSocket,
		&cfg.Audit.ArchiveDir} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

var agentName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	s := c.Server
	if s.HTTPListen == "" && s.AgentSocket == "" {
		fail("server: at least one of http_listen or agent_socket is required")
	}
	if s.AdminSocket == "" {
		fail("server: admin_socket is required")
	}
	if s.HTTPListen != "" {
		host, _, err := net.SplitHostPort(s.HTTPListen)
		switch {
		case err != nil:
			fail("server.http_listen: %v", err)
		case !s.AllowRemote && !isLoopback(host):
			fail("server.http_listen: %q is not a loopback address; set allow_remote: true to expose it", s.HTTPListen)
		}
	}
	if s.AgentSocket != "" && s.AgentSocket == s.AdminSocket {
		fail("server: agent_socket and admin_socket must differ")
	}
	if c.Database == "" {
		fail("database is required")
	}
	if c.PolicyFile == "" {
		fail("policy_file is required")
	}
	c.Limits.validate("limits", fail)
	if c.Audit.RetentionDays < 0 || c.Audit.RetentionDays > 36500 {
		fail("audit.retention_days must be between 0 (keep forever) and 36500")
	}
	if c.Approvals.TTL < time.Minute || c.Approvals.TTL > 24*time.Hour {
		fail("approvals.ttl must be between 1m and 24h")
	}
	for name, d := range map[string]time.Duration{"read": c.Timeouts.Read, "mutating": c.Timeouts.Mutating} {
		if d <= 0 || d > 10*time.Minute {
			fail("timeouts.%s must be in (0, 10m]", name)
		}
	}
	if c.Admin.TokenSHA256 != "" && !auth.ValidHash(c.Admin.TokenSHA256) {
		fail("admin.token_sha256 must be 64 lowercase hex characters")
	}
	if c.Admin.TokenSHA256 != "" && s.HTTPListen == "" {
		fail("admin.token_sha256 requires server.http_listen")
	}
	names := make([]string, 0, len(c.Agents))
	for n := range c.Agents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !agentName.MatchString(n) {
			fail("agents: invalid agent name %q", n)
		}
		if c.Agents[n].TokenSHA256 == c.Admin.TokenSHA256 && c.Admin.TokenSHA256 != "" {
			fail("agents.%s: must not reuse the admin token", n)
		}
		if c.Agents[n].Limits != nil {
			c.LimitsFor(n).validate("agents."+n+".limits", fail)
		}
	}
	if _, err := auth.NewAuthenticator(c.AgentHashes()); err != nil {
		fail("agents: %v", err)
	}
	c.Notifications.validate(fail)
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		fail("log.level must be debug, info, warn or error")
	}
	return errors.Join(errs...)
}

// AgentHashes returns agent name -> token hash.
func (c *Config) AgentHashes() map[string]string {
	out := make(map[string]string, len(c.Agents))
	for n, a := range c.Agents {
		out[n] = a.TokenSHA256
	}
	return out
}

// AgentNames returns the set of configured agents.
func (c *Config) AgentNames() map[string]bool {
	out := make(map[string]bool, len(c.Agents))
	for n := range c.Agents {
		out[n] = true
	}
	return out
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

package policy

import (
	"strings"
	"testing"
)

var known = Known{
	Agents: map[string]bool{"opencode": true, "blue": true},
	Permissions: map[string]map[string]bool{
		"system.read":     {},
		"service.read":    {"service": true},
		"logs.read":       {"service": true},
		"service.start":   {"service": true},
		"service.stop":    {"service": true},
		"service.restart": {"service": true},
	},
}

const doc = `
version: 1
agents:
  opencode:
    allow: [system.read, service.read, logs.read]
    ask:   [service.*]
    deny:  [shell.exec]
    resources:
      service:
        nginx.service:      { restart: allow }
        postgresql.service: { stop: deny }
        "sysrail-test-*.service": { start: allow, logs.read: deny }
  blue:
    allow: ["*"]
    deny:  [service.stop]
`

func compile(t *testing.T, src string) *Policy {
	t.Helper()
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(f, known)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecide(t *testing.T) {
	p := compile(t, doc)
	tests := []struct {
		agent, perm, kind, resource string
		want                        Action
	}{
		{"opencode", "system.read", "", "", Allow},
		{"opencode", "service.read", "service", "nginx.service", Allow},
		{"opencode", "service.restart", "service", "nginx.service", Allow},        // resource beats domain wildcard
		{"opencode", "service.restart", "service", "redis.service", Ask},          // domain wildcard
		{"opencode", "service.stop", "service", "postgresql.service", Deny},       // resource deny
		{"opencode", "service.start", "service", "sysrail-test-a.service", Allow}, // glob
		{"opencode", "logs.read", "service", "sysrail-test-a.service", Deny},      // glob deny beats exact allow
		{"opencode", "logs.read", "service", "nginx.service", Allow},
		{"opencode", "shell.exec", "", "", Deny},
		{"opencode", "storage.read", "", "", Deny}, // default deny
		{"blue", "storage.read", "", "", Allow},    // "*"
		{"blue", "service.stop", "service", "nginx.service", Deny},
		{"unknown", "system.read", "", "", Deny},
	}
	for _, tt := range tests {
		d := p.Decide(tt.agent, tt.perm, tt.kind, tt.resource)
		if d.Action != tt.want {
			t.Errorf("Decide(%s, %s, %s) = %s (%s), want %s", tt.agent, tt.perm, tt.resource, d.Action, d.Rule, tt.want)
		}
		if d.Rule == "" {
			t.Errorf("Decide(%s, %s) has no rule", tt.agent, tt.perm)
		}
	}
}

func TestAskWinsTiesAndDenyWinsAlways(t *testing.T) {
	p := compile(t, `
version: 1
agents:
  opencode:
    allow: [service.*]
    deny: [service.stop]
    resources:
      service:
        nginx.service: { stop: allow, restart: ask }
        "ngin*": { restart: allow }
`)
	if d := p.Decide("opencode", "service.stop", "service", "nginx.service"); d.Action != Deny {
		t.Fatalf("deny must beat a resource allow, got %s", d.Action)
	}
	if d := p.Decide("opencode", "service.restart", "service", "nginx.service"); d.Action != Ask {
		t.Fatalf("exact resource ask must beat glob allow, got %s", d.Action)
	}
}

func TestReachable(t *testing.T) {
	p := compile(t, doc)
	tests := []struct {
		agent, perm string
		want        bool
	}{
		{"opencode", "system.read", true},
		{"opencode", "service.stop", true}, // via service.* ask
		{"opencode", "storage.read", false},
		{"opencode", "shell.exec", false},
		{"blue", "service.stop", false}, // permission-level deny
		{"blue", "service.start", true},
		{"nobody", "system.read", false},
	}
	for _, tt := range tests {
		if got := p.Reachable(tt.agent, tt.perm); got != tt.want {
			t.Errorf("Reachable(%s, %s) = %v, want %v", tt.agent, tt.perm, got, tt.want)
		}
	}
	resourceOnly := compile(t, `
version: 1
agents:
  opencode:
    resources:
      service:
        nginx.service: { restart: allow }
`)
	if !resourceOnly.Reachable("opencode", "service.restart") {
		t.Fatal("resource-scoped grant must make the permission reachable")
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"version", "version: 2\n", "unsupported version"},
		{"unknown field", "version: 1\nagents:\n  opencode:\n    alow: [system.read]\n", "field alow not found"},
		{"unknown agent", "version: 1\nagents:\n  ghost:\n    allow: [system.read]\n", "not configured"},
		{"typo permission", "version: 1\nagents:\n  opencode:\n    allow: [service.stpo]\n", "unknown permission"},
		{"typo deny", "version: 1\nagents:\n  opencode:\n    deny: [service.stpo]\n", "unknown permission"},
		{"unknown domain", "version: 1\nagents:\n  opencode:\n    allow: [servce.*]\n", "unknown permission domain"},
		{"conflict", "version: 1\nagents:\n  opencode:\n    allow: [system.read]\n    deny: [system.read]\n", "both"},
		{"bad action", "version: 1\nagents:\n  opencode:\n    resources:\n      service:\n        a.service: { stop: maybe }\n", "unknown action"},
		{"unscoped permission", "version: 1\nagents:\n  opencode:\n    resources:\n      service:\n        a.service: { system.read: allow }\n", "cannot be scoped"},
		{"unknown kind", "version: 1\nagents:\n  opencode:\n    resources:\n      container:\n        a: { stop: allow }\n", "cannot be scoped"},
		{"bad glob", "version: 1\nagents:\n  opencode:\n    resources:\n      service:\n        \"[\": { stop: allow }\n", "bad pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse([]byte(tt.src))
			if err == nil {
				_, err = Compile(f, known)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestReservedPermissionsAreAccepted(t *testing.T) {
	p := compile(t, "version: 1\nagents:\n  opencode:\n    deny: [shell.exec, storage.modify, apps.*]\n")
	if d := p.Decide("opencode", "apps.restart", "", ""); d.Action != Deny {
		t.Fatalf("got %s", d.Action)
	}
}

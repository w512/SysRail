// Package testutil builds a fully wired engine backed by the fake provider
// and a temporary SQLite database, for use in tests.
package testutil

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/auth"
	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/engine"
	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/core/policy"
	"github.com/w512/SysRail/internal/providers/fake"
	"github.com/w512/SysRail/internal/store/sqlite"
)

// Policy grants "agent" reads and approval-gated restarts (auto-allowed for
// the "auto" widget); "other" may only read.
const Policy = `
version: 1
agents:
  agent:
    allow: [fake.read]
    ask: [fake.restart]
    resources:
      widget:
        auto: { fake.restart: allow }
  other:
    allow: [fake.read]
`

// Env is a wired test environment.
type Env struct {
	Engine *engine.Engine
	Store  *sqlite.Store
	Fake   *fake.Provider
	Auth   *auth.Authenticator
	Bus    *events.Bus
	// Tokens maps agent name to bearer token.
	Tokens map[string]string
}

// NewEnv builds an environment with agents "agent" and "other". opts may
// adjust the engine options, e.g. to set limits.
func NewEnv(t testing.TB, policyYAML string, opts ...func(*engine.Options)) *Env {
	t.Helper()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "sysrail.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	fp := fake.New()
	reg, err := core.NewRegistry(core.RegistryOptions{}, append(engine.Builtins(store), fp.Capabilities()...)...)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	hashes := map[string]string{}
	for _, name := range []string{"agent", "other"} {
		tok, hash, err := auth.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		tokens[name], hashes[name] = tok, hash
	}
	authn, err := auth.NewAuthenticator(hashes)
	if err != nil {
		t.Fatal(err)
	}
	f, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Compile(f, policy.Known{
		Agents:      map[string]bool{"agent": true, "other": true},
		Permissions: reg.Permissions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	bus := events.NewBus(256)
	eo := engine.Options{Registry: reg, Policy: pol, Store: store, ApprovalTTL: 10 * time.Minute, Events: bus}
	for _, o := range opts {
		o(&eo)
	}
	eng, err := engine.New(eo)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{Engine: eng, Store: store, Fake: fp, Auth: authn, Bus: bus, Tokens: tokens}
}

# Development guide

This guide explains how the code is organized, how to build and test it, and
how to add capabilities and providers. For the threat model that every change
has to respect, read [security.md](security.md) first.

## Requirements

- Go: `go.mod` pins the toolchain (currently go1.26.6), and any Go 1.21 or
  newer downloads it automatically. Don't lower the pin; it carries standard
  library security fixes.
- `make`.
- macOS or Linux for development. Unit tests run on both.
- For integration and end-to-end tests: a Linux amd64 machine with systemd,
  reachable over SSH by a user with passwordless sudo. It doesn't need Go.
  Use a dedicated test machine or VM: the end-to-end run installs SysRail
  system-wide and later deletes its user and groups.

## Repository layout

| Path | What lives there |
|---|---|
| `cmd/sysrail` | The single binary: `serve`, `mcp`, `approvals`, `audit`, `token`, `policy`, `version` |
| `internal/core` | Capability model (`core.Define`), registry rules, structured errors, IDs |
| `internal/core/engine` | The request pipeline shared by every transport; approvals; `request_get_status` |
| `internal/core/policy` | Policy parsing, validation and evaluation |
| `internal/core/audit`, `internal/core/request` | Audit record and request types and storage interfaces |
| `internal/core/redact` | Secret masking |
| `internal/core/events` | In-memory event bus |
| `internal/store/sqlite` | SQLite storage (pure Go, embedded migrations) |
| `internal/api/httpapi` | Agent and admin HTTP APIs, SSE |
| `internal/api/mcpshim` | The stdio MCP proxy behind `sysrail mcp` |
| `internal/server` | Daemon wiring: listeners, sockets, policy reload, event watchers |
| `internal/config`, `internal/auth`, `internal/client` | Configuration, tokens, API client |
| `internal/providers/linux`, `internal/providers/systemd` | Providers |
| `internal/providers/fake`, `internal/providers/providertest` | Test provider and the provider contract test |
| `internal/testutil` | An engine wired to the fake provider, for transport tests |
| `deploy/` | systemd unit, polkit rule, example config and policy, install scripts |
| `deploy/test/` | Overlay installed on the test machine only |
| `test/e2e` | End-to-end tests against a deployed daemon |
| `scripts/` | Remote test, deploy and cleanup scripts |

## How a call flows

Every transport ends up in `engine.Execute`:

1. Look up the capability by ID.
2. Bind the arguments: JSON schema validation, strict decoding, then the
   capability's own `validate` function, which normalizes the input and
   returns the target resource.
3. Evaluate the policy for the agent's permission and that resource.
4. Write the `request` audit record. If this write fails, stop.
5. One of three outcomes:
   - **deny:** return `PERMISSION_DENIED`;
   - **ask:** store a pending request;
   - **allow:** run the capability with its timeout, redact the result, and
     write the `result` record.

Approvals (`engine.Approve`) re-bind the stored arguments, compare their hash,
re-check the policy and then run the same execution path.

`sysrail mcp` and the HTTP API contain no business logic. Keep it that way:
new behavior belongs in the engine or in a provider.

## Build and test

| Command | What it does |
|---|---|
| `make test` | Unit tests (macOS or Linux) |
| `make check` | gofmt, `go vet` and staticcheck for darwin and linux (with the `integration` tag), then tests |
| `make vulncheck` | govulncheck; must report no vulnerabilities |
| `make build` | Binary for the current OS in `build/sysrail` |
| `make build-linux` | Static linux/amd64 binary in `build/linux-amd64/sysrail` |
| `make test-remote` | Cross-compiles every package's tests with `-tags integration` and runs them on the test machine as root |
| `make deploy-remote` / `make undeploy-remote` | Installs the current build with `deploy/test/`, or removes everything again |
| `make e2e-remote` | Deploys, runs `test/e2e` through the real `sysrail mcp`, and always cleans up |

The remote scripts take these environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SYSRAIL_TEST_HOST` | the maintainer's test machine | SSH destination, e.g. `you@testbox` |
| `PKGS` | `./...` | Packages for `test-remote` |
| `ARGS` | none | Extra test flags, e.g. `-test.v -test.run TestHost` |
| `TAGS` | `integration` | Build tags |
| `SUDO` | `1` | Set to `0` to run tests without sudo |

```sh
SYSRAIL_TEST_HOST=you@testbox PKGS=./internal/providers/systemd/ ARGS=-test.v make test-remote
```

### Test levels

- **Unit tests** run anywhere. Providers reach the host only through their
  `Options` (filesystem root, command runner, systemd manager, journal
  reader), so tests use fakes and fixture trees under `testdata/root` that
  mirror real `/proc`, `/sys` and `/etc` files. Sanitize fixtures: no real
  hostnames, public IPs or user names.
- **Contract tests**: every provider calls `providertest.Run` with example
  arguments for each read capability. It checks that capabilities register,
  reject unknown arguments, and return a JSON object or a structured error.
- **Integration tests** (`//go:build linux && integration`) use the real
  host. Tests that need root skip without it. They may only touch units named
  `sysrail-test-*`, and they remove everything they create in `t.Cleanup`.
  The test machine runs real services.
- **End-to-end tests** (`//go:build linux && e2e`, in `test/e2e`) drive a
  deployed daemon through the real binary, as an agent host would.
- **Transport tests** use `internal/testutil`, which wires the engine to the
  fake provider and a temporary SQLite database.

On macOS, Unix socket paths are limited to 104 bytes. Tests that create
sockets use `os.MkdirTemp("/tmp", …)` instead of `t.TempDir()`.

## Adding a capability

A capability is created with `core.Define` from an input type, an optional
`validate` function, and a `run` function. Here is a read capability for the
Linux provider:

```go
type uptimeArgs struct {
	Pretty bool `json:"pretty,omitempty" jsonschema:"Also return a human-readable duration"`
}

type uptimeResult struct {
	Seconds int64  `json:"seconds"`
	Pretty  string `json:"pretty,omitempty"`
}

func (p *Provider) uptimeCapability() core.Capability {
	return core.Define(core.Capability{
		ID:          "system.uptime",
		Tool:        "system_get_uptime",
		Description: "Get how long the host has been running.",
		Risk:        core.RiskRead,
		Permission:  "system.read",
	}, nil, func(ctx context.Context, in uptimeArgs) (any, error) {
		b, err := readFile(p.opts.Root, "proc/uptime")
		if err != nil {
			return nil, unavailable("uptime", err)
		}
		up, err := parseUptime(b)
		if err != nil {
			return nil, unavailable("uptime", err)
		}
		out := uptimeResult{Seconds: int64(up)}
		if in.Pretty {
			out.Pretty = (time.Duration(up) * time.Second).String()
		}
		return out, nil
	})
}
```

The input schema is inferred from the struct. Fields without `omitempty` are
required, and unknown fields are rejected. Add enums and bounds with
`core.SchemaFor`, and normalize or reject input in `validate`:

```go
type serviceArgs struct {
	Name string `json:"name" jsonschema:"Service name, e.g. nginx or nginx.service"`
}

core.Define(core.Capability{
	ID:           "service.reload",
	Tool:         "service_reload",
	Description:  "Reload a service's configuration without restarting it.",
	Impact:       "The service re-reads its configuration; a bad configuration can break it.",
	Risk:         core.RiskLow,
	Permission:   "service.reload", // mutating: must equal the ID
	Mutating:     true,
	ResourceKind: "service", // enables per-service policy rules
	InputSchema: core.SchemaFor[serviceArgs](func(p map[string]*jsonschema.Schema) {
		p["name"].MaxLength = core.Ptr(255)
	}),
}, func(in *serviceArgs) (string, error) {
	name, err := NormalizeUnit(in.Name) // INVALID_ARGUMENT on bad input
	if err != nil {
		return "", err
	}
	in.Name = name // the normalized arguments are what gets hashed and audited
	return name, nil // the resource the policy is evaluated against
}, run)
```

The registry rejects capabilities that break these rules at startup:

- The ID is dotted lowercase (`domain.verb`). The tool name is
  `<domain>_<verb>[_<object>]`, at most 64 characters. Neither may contain
  generic execution words such as `exec`, `execute`, `run`, `command`, `cmd`,
  `shell`, `eval`, `script` or `sudo`.
- A read capability has risk `read` and a `<domain>.read` permission.
- A mutating capability has risk `low` or higher, a non-empty `Impact` (shown
  to approvers), and a permission equal to its ID.
- The arguments `reason` and `idempotency_key` are reserved; the engine adds
  them to mutating tools.
- The timeout is at most 10 minutes. Leave it at zero to use the configured
  default.

Conventions for `run`:

- **Results** are JSON objects: return a struct. Don't return environment
  variables or credentials. The engine redacts results, but treat that as a
  safety net, not a feature.
- **Errors** are structured. Choose the code that tells the agent what to do:
  - `INVALID_ARGUMENT` for bad input;
  - `RESOURCE_NOT_FOUND` for an unknown resource;
  - `PERMISSION_DENIED` for a hard refusal, such as a protected unit (return
    it from `validate` so nothing runs);
  - `PROVIDER_UNAVAILABLE` when a host source cannot be reached;
  - `CONFLICT` and `TIMEOUT` where they fit.

  Plain errors become `EXECUTION_FAILED` with a redacted message.
- **Respect `ctx`.** It carries the timeout. The engine detaches mutations
  from client cancellation, so they always finish or time out.
- **Helpers:** run them with `exec.CommandContext`, a fixed argument list and
  a fixed environment, never through a shell. Pass user input only as a
  validated argument, using the `--flag=value` form so it can't be read as an
  option.
- **Platform code:** keep `go build ./...` working on macOS. Put Linux-only
  code behind `//go:build linux`, with a `_other.go` stub that returns
  `PROVIDER_UNAVAILABLE`.

Then:

1. Add the capability to the provider's `Capabilities()` and add an example
   for it to the provider's contract test.
2. Write unit tests against fixtures or fakes. If the capability touches the
   real system, add an integration test.
3. If it changes services, check the polkit rules. `deploy/50-sysrail.rules`
   and `deploy/test/50-sysrail.rules` only allow the `start`, `stop` and
   `restart` verbs, so a new systemd verb such as `reload` must be added
   there too.
4. Update the tools table in `README.md` and the tools and permissions tables
   in `docs/usage.md`.

New permissions become valid in policies automatically, because the policy
validator takes the known permissions from the registry. Host events about a
resource kind are shown to agents that hold `<kind>.read` for that resource.

## Adding a provider

1. Create `internal/providers/<name>` with a type that implements
   `providers.Provider` (`Name()` and `Capabilities()`). The constructor must
   not touch the host: `sysrail policy check` builds providers too.
2. Route all host access through an `Options` struct with production
   defaults, so tests can substitute fakes.
3. To emit events, implement `providers.EventSource`
   (`Watch(ctx, publish)`). The daemon runs it until shutdown.
4. Add a section under `providers` in `internal/config` with an `enabled`
   flag, and construct the provider in `cmd/sysrail/providers.go`.
5. Call `providertest.Run` from the provider's tests.
6. Deploy it with `make deploy-remote` and exercise it under the real
   systemd sandbox. A new system call, device or path can be blocked by the
   unit. Find blocked system calls with `sudo journalctl -k | grep type=1326`.
   Loosen the unit only as much as needed, and explain why in a comment.

## Contribution conventions

- Make small, focused commits with an imperative subject line, such as
  "Add GPU status via nvidia-smi and sysfs".
- Before committing, run `make check`. Also run `make test-remote` when you
  touch providers, and `make e2e-remote` when you touch the daemon, the unit
  or the install scripts.
- The project name in code, units, metrics and files is `sysrail`.
- Contributions are accepted under the terms in [LICENSE.md](../LICENSE.md).

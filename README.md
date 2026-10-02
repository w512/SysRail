# SysRail

SysRail is a permissioned control plane that lets AI agents inspect and manage
Linux systems without giving them a shell, root, or the Docker socket.

Agents get typed tools such as `service_get_logs` or `service_restart`
instead of `execute("…")`. Every call is checked against a policy, sensitive
actions wait for a human to approve them, and everything is recorded in an
append-only audit log.

![SysRail architecture: an AI agent talks MCP over stdio to the unprivileged sysrail mcp proxy, which forwards calls over a Unix socket to the sandboxed sysrail daemon. The daemon checks policy, waits for an administrator's approval when needed, audits every call before it runs, and uses providers to read /proc and /sys, manage systemd over D-Bus through polkit, read journald and query GPUs.](docs/architecture.svg)

Status: Stage 1, generic Linux (`linux/amd64`, systemd).

Documentation: [installation guide](docs/install.md) ·
[usage guide](docs/usage.md) · [HTTP API reference](docs/api.md) ·
[security model](docs/security.md) · [development guide](docs/development.md).

## Tools

| Tool | What it does | Permission | Risk |
|---|---|---|---|
| `system_get_status` | Hostname, OS, kernel, uptime, load, memory, processes | `system.read` | read |
| `system_get_cpu_status` | CPU model, utilization, frequency | `system.read` | read |
| `system_get_memory_status` | RAM and swap usage | `system.read` | read |
| `system_get_gpu_status` | GPUs via nvidia-smi and sysfs | `system.read` | read |
| `storage_get_status` | Filesystem space and inode usage with warnings | `storage.read` | read |
| `storage_list_mounts` | Mounts, plus fstab entries that are not mounted | `storage.read` | read |
| `network_get_connections` | Listening sockets and connections | `network.read` | read |
| `service_list` | systemd services and their states | `service.read` | read |
| `service_get_status` | Detailed service status | `service.read` | read |
| `service_get_logs` | Recent journal entries (secrets redacted) | `logs.read` | read |
| `service_start` | Start a service | `service.start` | low |
| `service_restart` | Restart a service | `service.restart` | low |
| `service_stop` | Stop a service | `service.stop` | medium |
| `request_get_status` | Outcome of your own request that needed approval | — | read |

Agents only see the tools their policy can ever allow. There is no generic
execution tool, and the registry refuses to load one.

## Install

Requirements: Linux on amd64 with systemd and polkit (JavaScript rules, e.g.
Ubuntu 24.04). Building needs `git`, `make` and Go 1.26 or newer. An older Go
(1.21+) also works: it downloads the toolchain pinned in `go.mod`.

The [installation guide](docs/install.md) covers configuration, adding agents,
upgrades and troubleshooting in detail.

### Option 1: build and install on the Linux host

```sh
sudo apt install -y git make          # Debian/Ubuntu
sudo snap install go --classic        # or install Go from https://go.dev/dl/
git clone https://github.com/w512/SysRail.git
cd SysRail
make build-linux                      # build/linux-amd64/sysrail (static, no cgo)
sudo ./deploy/install.sh build/linux-amd64/sysrail
```

### Option 2: build on another machine and copy it over

This keeps Go off the server. The build works from macOS too.

```sh
git clone https://github.com/w512/SysRail.git
cd SysRail
make build-linux                      # build/linux-amd64/sysrail (static, no cgo)
ssh host mkdir -p /tmp/sysrail
scp -r build/linux-amd64/sysrail deploy host:/tmp/sysrail/
ssh -t host 'cd /tmp/sysrail && sudo ./deploy/install.sh ./sysrail'
```

### After installing

Either way, `install.sh` creates the `sysrail` system user and the
`sysrail-agents` group, installs the sandboxed `sysrail.service` and a polkit
rule, writes `/etc/sysrail/config.yaml` and `policy.yaml` from the examples,
and prints a token for an agent named `opencode` once. Existing configuration
is never overwritten. Remove SysRail with `sudo ./deploy/uninstall.sh` (add
`--purge` to delete configuration and the audit log).

Then:

1. Edit `/etc/sysrail/policy.yaml` (see [Policy](#policy)).
2. List the services the daemon may manage in
   `/etc/polkit-1/rules.d/50-sysrail.rules`. It manages none by default.
3. Add the users that run agents to the agent group:
   `sudo usermod -aG sysrail-agents <user>`.

Create more agents with `sysrail token create`: put `token_sha256` under
`agents.<name>` in the config and give the token to the agent. Only hashes are
stored.

## Connecting an agent

The agent host runs `sysrail mcp`, which serves MCP over stdio and forwards
every call to the daemon. It holds no privileges of its own.

OpenCode (`opencode.jsonc`):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "sysrail": {
        "type": "local",
        "command": ["sysrail", "mcp"],
        "environment": { "SYSRAIL_TOKEN": "{env:SYSRAIL_TOKEN}" },
      },
    },
  },
}
```

Claude Code:

```sh
claude mcp add sysrail -e SYSRAIL_TOKEN=sysrail_… -- sysrail mcp
```

`sysrail mcp` connects to `unix:///run/sysrail/agent.sock` by default. Use
`--url http://127.0.0.1:9487` for TCP and `--token-file` to keep the token out
of the environment. The [usage guide](docs/usage.md) covers agents on another
machine, the tools, policies, approvals, the audit log and the HTTP API.

## Policy

```yaml
version: 1
agents:
  opencode:
    allow: [system.read, storage.read, network.read, service.read, logs.read]
    ask: [service.start, service.restart]
    deny: [service.stop]
    resources:
      service:
        nginx.service: { restart: allow }
```

- `allow` runs immediately, `ask` waits for approval, and `deny` always refuses.
- Any matching `deny` wins. Otherwise the most specific rule decides: exact
  resource, then resource glob, then exact permission, then `domain.*`, then
  `*`. If an `allow` and an `ask` are equally specific, `ask` wins.
- Anything that no rule matches is denied.
- Typos are errors. Unknown permissions, agents or fields stop the daemon from
  starting or reloading.

Check a policy and see each agent's effective grants with
`sysrail policy check`. Apply changes with `systemctl reload sysrail`.

Some units can never be changed, whatever the policy says: `sysrail.service`
always, plus dbus, `systemd-*`, polkit, ssh, `user@*` and `getty@*` by default
(`providers.systemd.protected_units`). The polkit rule enforces a second,
OS-level allow-list.

## Approvals

When a call needs approval, the agent gets
`{"status": "approval_required", "request_id": "req_…"}`. It then polls
`request_get_status`, which can wait up to 30 seconds. A human decides on the
host:

```sh
sudo sysrail approvals list
sudo sysrail approvals show req_…
sudo sysrail approvals approve req_… [--note "…"]   # shows the request and asks; --yes skips
sudo sysrail approvals deny req_… [--note "…"]
```

Configure notifications through ntfy, Telegram, email or a webhook to hear
about new requests (`sudo sysrail notify test` checks them). Each message
includes the approve and deny commands. Approval itself works only through
the admin socket (`/run/sysrail/admin.sock`, mode 0600), so an agent can never
approve its own request. The daemon executes the stored arguments exactly as
requested and re-checks the policy first. Pending requests expire after
`approvals.ttl` (15 minutes by default). Mutating calls accept an
`idempotency_key`, which makes retries safe.

## Audit and events

```sh
sudo sysrail audit                       # latest records
sudo sysrail audit --follow              # stream new records
sudo sysrail audit --request req_… --json
```

Every call is audited before anything runs, reads included. If the audit log
cannot be written, the request is refused. Each agent has a call budget (by
default 120 calls a minute, 30 back to back) and may leave at most 10
requests waiting for approval. Calls over the budget fail with
`RATE_LIMITED`. Records are kept for 90 days by
default, then written to compressed archives and removed from the database.

`GET /v1/events` streams Server-Sent Events: request lifecycle events and
`service.failed` / `service.recovered`. Agents receive their own requests'
events plus host events about resources they may read.

## HTTP API

The agent API (bearer token, on `127.0.0.1:9487` and the agent socket):

| Method | Path | |
|---|---|---|
| GET | `/v1/capabilities` | Tools this agent can reach, with input schemas |
| POST | `/v1/execute` | `{"capability", "arguments", "reason", "idempotency_key"}` |
| GET | `/v1/requests/{id}?wait=N` | Status of your own request |
| GET | `/v1/events` | SSE stream |

The admin API (admin socket, or `admin.token_sha256` over TCP) adds
`GET /v1/requests`, `POST /v1/requests/{id}/approve|deny` and `GET /v1/audit`.
Errors are always structured, for example
`{"error": {"code": "PERMISSION_DENIED", "message": "…", "retryable": false}}`.

## Security model

- The model, prompts, tool arguments and log contents are untrusted. Policy is
  enforced by the daemon, independently of the agent.
- There is no shell or arbitrary command execution. Helper binaries
  (`journalctl`, `nvidia-smi`) run with fixed arguments and no shell.
- Service management goes through systemd over D-Bus as an unprivileged user.
  polkit decides which units that user may touch.
- The daemon runs sandboxed with no capabilities, a read-only system, and a
  syscall filter.
- Secrets in results, logs and audit arguments (passwords, tokens, keys,
  JWTs, URL credentials) are redacted on a best-effort basis.
- Agent tokens are stored as SHA-256 hashes and compared in constant time.
  The audit table rejects updates and deletes.

SysRail only controls what passes through it: an agent whose host also gives
it a shell, sudo or the Docker group can bypass it. The
[security model](docs/security.md) covers this and the other limitations, and
ends with a hardening checklist. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## Development

```sh
make test          # unit tests (macOS or Linux)
make check         # gofmt, vet, staticcheck for darwin and linux, tests
make vulncheck     # govulncheck
make test-remote   # cross-compile tests (-tags integration) and run them on the Linux test host
make e2e-remote    # deploy to the test host, run test/e2e through the real `sysrail mcp`, clean up
```

Code layout: `internal/core` holds the capability registry, policy, engine,
audit, redaction and events. `internal/providers` holds `linux` and
`systemd`, which must pass `providertest`. `internal/api` contains `httpapi`
and the `mcpshim` stdio proxy. `cmd/sysrail` is the CLI.

The [development guide](docs/development.md) explains the request pipeline,
the test levels and the remote test machine, and how to add capabilities and
providers.

## License

SysRail is licensed under the [Prosperity Public License 3.0.0](LICENSE.md). It
is free for noncommercial use, and companies may try it for commercial
purposes for thirty days. For a commercial license, contact Nick Blokhin
<nick@blokhin.us>.

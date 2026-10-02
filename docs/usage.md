# Using SysRail

This guide covers connecting agents, the tools they get, writing policies,
approving requests, and reading the audit log. It assumes SysRail is
installed; see [install.md](install.md).

## How it works

- **Agents** authenticate with a token. Each token belongs to one named agent
  in `/etc/sysrail/config.yaml`.
- **Tools** are typed operations such as `service_get_logs` or
  `service_restart`. There is no shell and no generic "run a command" tool.
- **Policy** decides each call: `allow` runs it, `ask` waits for a human, and
  `deny` refuses it.
- **Approvals** are given by an administrator on the server with
  `sudo sysrail approvals`. Agents cannot approve anything.
- **Audit:** every call is recorded before it runs, including reads and
  refusals.

## Connecting an agent

The agent host starts `sysrail mcp`, which speaks MCP over stdio and forwards
each call to the daemon. It needs a token and access to the agent socket: the
user must be in the `sysrail-agents` group.

| Setting | Flag | Environment | Default |
|---|---|---|---|
| Token | — | `SYSRAIL_TOKEN` | — |
| Token file | `--token-file` | `SYSRAIL_TOKEN_FILE` | — |
| Daemon address | `--url` | `SYSRAIL_URL` | `unix:///run/sysrail/agent.sock` |

A file keeps the token out of process environments and configuration:

```sh
mkdir -p ~/.config/sysrail
install -m 600 /dev/null ~/.config/sysrail/token
$EDITOR ~/.config/sysrail/token          # paste the token
```

### OpenCode

`opencode.jsonc` (project) or `~/.config/opencode/opencode.jsonc` (global):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "sysrail": {
        "type": "local",
        "command": ["sysrail", "mcp", "--token-file", "/home/alice/.config/sysrail/token"],
      },
    },
  },
}
```

OpenCode sends its session ID with each call. SysRail records it, so audit
entries can be traced back to the conversation that made them.

### Claude Code

```sh
claude mcp add sysrail -- sysrail mcp --token-file /home/alice/.config/sysrail/token
```

### Other MCP clients

Configure a stdio server with the command `sysrail mcp` and either
`SYSRAIL_TOKEN` or `--token-file`.

### Agent on another machine

The daemon listens only on the server itself. Run `sysrail mcp` on the server
over SSH; MCP's stdio transport passes through SSH unchanged:

```jsonc
"command": ["ssh", "server", "sysrail", "mcp", "--token-file", ".config/sysrail/token"]
```

The SSH user on the server needs to be in `sysrail-agents`. Key-based login
without a passphrase prompt (or an SSH agent) is required, because the agent
host cannot answer prompts.

Alternatively, tunnel the HTTP port and run a locally built `sysrail` (for
example from `make build`) against it:

```sh
ssh -N -L 9487:127.0.0.1:9487 server &
sysrail mcp --url http://127.0.0.1:9487 --token-file ~/.config/sysrail/token
```

## Tools

The agent only sees tools its policy can ever allow. Service names accept
`nginx` or `nginx.service`; only `.service` units are supported.

| Tool | Arguments | Returns |
|---|---|---|
| `system_get_status` | — | Hostname, OS, kernel, uptime, load, CPU count, memory, processes |
| `system_get_cpu_status` | `per_cpu` (bool) | Model, utilization (sampled over 250 ms), frequency |
| `system_get_memory_status` | — | RAM and swap in bytes |
| `system_get_gpu_status` | — | GPUs with memory, utilization, temperature, power; `available: false` if none |
| `storage_get_status` | — | Every real filesystem with space and inode usage; `warning` at 90%, `critical` at 95% |
| `storage_list_mounts` | `include_pseudo` (bool) | Mounts, plus `fstab_not_mounted`: fstab entries that should be mounted but are not |
| `network_get_connections` | `state`: `listen` (default), `established`, `all`; `protocol`: `tcp`, `udp`, `all`; `port`; `limit` (≤ 2000) | Sockets with addresses, ports, state and owner UID |
| `service_list` | `pattern` (glob, e.g. `nginx*`); `state`: `all`, `active`, `inactive`, `failed`, `running`; `limit` (≤ 1000) | Loaded services and their states |
| `service_get_status` | `name` | States, `healthy`, main PID, restart count, exit status, memory, state change times |
| `service_get_logs` | `name`; `lines` (1–1000, default 100); `since_minutes` (≤ 10080); `priority` (`emerg` … `debug`) | Journal entries, oldest first, secrets redacted, capped at 256 KiB |
| `service_start` | `name` | Job result and the resulting state |
| `service_restart` | `name` | Job result and the resulting state |
| `service_stop` | `name` | Job result and the resulting state |
| `request_get_status` | `request_id`; `wait_seconds` (0–30) | Status and, when finished, the result of the agent's own request |

The three service-changing tools also accept:

- `reason` — up to 500 characters, shown to the approver. Agents should
  always send one.
- `idempotency_key` — a client-chosen key that makes retries safe. Repeating
  a call with the same key returns the original request instead of running it
  again.

Results and errors are JSON objects. Agents never have to parse terminal
output.

## Example: diagnosing a failed service

This is what an agent does when asked "why is nginx down?" under the default
policy.

1. **Find failed services.** `service_list` with `{"state": "failed"}`:

   ```json
   {"services": [{"name": "nginx.service", "active_state": "failed", "sub_state": "failed", ...}], "total": 1}
   ```

2. **Check the status.** `service_get_status` with `{"name": "nginx"}`:

   ```json
   {"name": "nginx.service", "active_state": "failed", "healthy": false, "restarts": 3,
    "exec_main_status": 1, "result": "exit-code", "state_changed_at": "2026-10-02T16:28:42Z", ...}
   ```

3. **Read the logs.** `service_get_logs` with `{"name": "nginx", "lines": 50}`:

   ```json
   {"unit": "nginx.service", "entries": [
     {"time": "...", "priority": "err", "identifier": "nginx",
      "message": "bind() to 0.0.0.0:80 failed (98: Address already in use)"}], "count": 1}
   ```

4. **Find what holds the port.** `network_get_connections` with
   `{"port": 80}`.

5. **Request a restart.** `service_restart` with
   `{"name": "nginx", "reason": "port 80 is free again"}`. The policy says
   `ask`, so nothing runs yet:

   ```json
   {"status": "approval_required", "request_id": "req_01M3YQHXHVNE03F458XMJQ3ANN",
    "expires_at": "...", "message": "A human must approve this request ..."}
   ```

6. **A human approves on the server** (see [Approving requests](#approving-requests)).

7. **Get the outcome.** `request_get_status` with
   `{"request_id": "req_01M3...", "wait_seconds": 30}`:

   ```json
   {"request_id": "req_01M3...", "status": "executed",
    "result": {"unit": "nginx.service", "action": "restart", "job_result": "done", "active_state": "active", ...}}
   ```

If the agent had tried `service_stop` instead, it would not even see the tool,
because the default policy denies `service.stop` outright. A call to a
protected unit such as `ssh` returns `PERMISSION_DENIED` whatever the policy
says.

## Writing a policy

`/etc/sysrail/policy.yaml` lists rules per agent:

```yaml
version: 1
agents:
  <agent-name>:
    allow: [<permission>, ...]
    ask:   [<permission>, ...]
    deny:  [<permission>, ...]
    resources:
      service:
        <unit name or glob>: { <verb or permission>: allow | ask | deny }
```

Permissions:

| Permission | Tools |
|---|---|
| `system.read` | `system_get_status`, `system_get_cpu_status`, `system_get_memory_status`, `system_get_gpu_status` |
| `storage.read` | `storage_get_status`, `storage_list_mounts` |
| `network.read` | `network_get_connections` |
| `service.read` | `service_list`, `service_get_status` |
| `logs.read` | `service_get_logs` |
| `service.start` / `service.restart` / `service.stop` | `service_start` / `service_restart` / `service_stop` |

`service.*` matches all service permissions and `*` matches everything. In
`resources`, a verb such as `restart` means `service.restart`; a full name
such as `logs.read` can be used too. `request_get_status` needs no permission:
an agent can only ever see its own requests.

How a call is decided:

1. If any matching rule says `deny`, the call is denied.
2. Otherwise the most specific matching rule wins: exact resource, then
   resource glob, then exact permission, then `domain.*`, then `*`. If an
   `allow` and an `ask` are equally specific, `ask` wins.
3. If nothing matches, the call is denied.

### Read-only monitoring agent

```yaml
agents:
  monitor:
    allow: [system.read, storage.read, network.read, service.read, logs.read]
```

### Restart one service freely, ask for the rest, never stop

```yaml
agents:
  opencode:
    allow: [system.read, storage.read, network.read, service.read, logs.read]
    ask: [service.start, service.restart]
    deny: [service.stop]
    resources:
      service:
        nginx.service: { restart: allow }
```

### Manage only one family of services

Nothing is granted for services in general; only `worker-*` units can be
restarted (with approval) or stopped (with approval):

```yaml
agents:
  deploy-bot:
    allow: [service.read, logs.read]
    resources:
      service:
        "worker-*.service": { restart: ask, stop: ask }
```

### Pitfall: deny always wins

```yaml
    deny: [service.stop]
    resources:
      service:
        nginx.service: { stop: allow }   # no effect: the deny above still matches
```

To allow something for a single resource only, don't deny the permission in
general. Leave it ungranted (it's denied by default) and allow it for that
resource, as in the `worker-*` example.

### Apply and check

```sh
sudo sysrail policy check     # validates and shows each agent's effective grants
sudo systemctl reload sysrail
```

Typos, unknown permissions, unknown agents and unknown keys are errors. An
invalid policy is never loaded: the daemon keeps running with the previous
one.

Two more limits apply regardless of policy. The polkit rule must also allow a
unit before SysRail can change it (see [install.md](install.md#2-polkit-rule)),
and protected units can never be changed.

## Approving requests

Approvals use the admin socket, which only root and the `sysrail` user can
open. Run these on the server:

```sh
sudo sysrail approvals list           # pending requests
sudo sysrail approvals list --all     # every request, newest first
sudo sysrail approvals show req_…     # details
sudo sysrail approvals approve req_… [--note "…"] [--yes]
sudo sysrail approvals deny req_… [--note "…"]
```

```text
$ sudo sysrail approvals list
ID                              AGENT     CAPABILITY       RESOURCE       RISK  STATUS   CREATED  EXPIRES
req_01M3YQHXHVNE03F458XMJQ3ANN  opencode  service.restart  nginx.service  low   pending  12s ago  in 14m48s
```

`approve` shows the request and asks for confirmation unless you pass
`--yes`:

```text
Request:     req_01M3YQHXHVNE03F458XMJQ3ANN
Status:      pending
Agent:       opencode
Capability:  service.restart (risk: low)
Resource:    nginx.service
Arguments:   {"name":"nginx.service"}
Impact:      Stops and starts the service again; its clients see a brief interruption.
Reason:      "port 80 is free again" (from the agent, unverified)
Policy:      opencode: ask service.restart
...
Approve and execute this request? [y/N] y
req_01M3YQHXHVNE03F458XMJQ3ANN: executed
result: {"action":"restart","active_state":"active","job_result":"done",...}
```

Things to know:

- **The reason is unverified.** It's written by the agent. The impact line
  comes from SysRail itself.
- **Approval runs the request immediately**, with exactly the arguments the
  agent sent. The policy is checked again first; if it now denies the call,
  the request fails instead of running.
- **Requests expire** after `approvals.ttl` (15 minutes by default).
- **Your note is visible to the agent** in `request_get_status`, which helps
  explain a denial.
- **The approver is recorded** from the socket's peer credentials, for
  example `uid=0(root) via alice`.
- **For scripts,** `--json` prints machine-readable output and
  `SYSRAIL_ADMIN_SOCKET` or `--socket` selects a different admin socket.

## Audit log

```sh
sudo sysrail audit                        # latest 50 records
sudo sysrail audit --limit 200 --agent opencode
sudo sysrail audit --capability service.restart
sudo sysrail audit --request req_…        # the full story of one request
sudo sysrail audit --follow               # stream new records
sudo sysrail audit --json                 # one JSON object per record
```

```text
ID  TIME                 EVENT     AGENT     CAPABILITY       RESOURCE       DECISION  RESULT             DETAIL
11  2026-10-02 18:35:58  request   opencode  service.restart  nginx.service  ask       approval_required  req_01M3...
12  2026-10-02 18:36:20  approval  opencode  service.restart  nginx.service  -         approved           by uid=0(root) via alice
13  2026-10-02 18:36:20  result    opencode  service.restart  nginx.service  -         success            by uid=0(root) via alice
16  2026-10-02 18:37:02  request   opencode  service.stop     nginx.service  deny      denied             PERMISSION_DENIED: ...
```

Event types:

- `request` is written before anything runs, for every call.
- `result` is written after a call ran.
- `approval` records a human decision or an expiry.

The `RESULT` column takes these values:

| Result | Meaning |
|---|---|
| `started` | Allowed by policy; about to run |
| `success` / `error` | The call ran and succeeded or failed (see `DETAIL`) |
| `denied` | Refused by policy or by a provider rule such as protected units |
| `invalid` | Bad arguments or an unknown capability |
| `approval_required` | Waiting for a human |
| `duplicate` | A retry with an `idempotency_key` that was already used |
| `approved` / `rejected` / `expired` | Outcome of a pending request |

Each record also stores the session ID, the arguments with secrets redacted,
and their SHA-256, the policy rule that decided, and the duration. If the
audit log cannot be written, the call is refused rather than run unrecorded.

The `audit_log` table rejects updates and deletes. There is no automatic
retention yet, so the database grows over time.

## Events

`GET /v1/events` streams Server-Sent Events:

| Type | When |
|---|---|
| `request.pending` | A call is waiting for approval |
| `request.approved`, `request.denied`, `request.expired` | A decision was made |
| `request.executed`, `request.failed` | An approved or allowed change finished |
| `service.failed` | A service entered the failed state (checked every 5 s) |
| `service.recovered` | A failed service became active again |

An agent receives events about its own requests, plus `service.*` events for
services its policy lets it read (`service.read`). The admin socket receives
everything.

```sh
# As an agent
curl -N -H "Authorization: Bearer $SYSRAIL_TOKEN" \
  "http://127.0.0.1:9487/v1/events?types=service.failed,request.executed"

# As an administrator
sudo curl -N --unix-socket /run/sysrail/admin.sock http://sysrail/v1/events
```

```text
id: 6
event: service.failed
data: {"id":6,"time":"2026-10-02T16:42:57Z","type":"service.failed","source":"systemd","resource_kind":"service","resource":"nginx.service","data":{"active_state":"failed","previous_state":"active","sub_state":"failed"}}
```

The last 1024 events are kept in memory. Reconnect with the `Last-Event-ID`
header (or `?since=<id>`) to receive what you missed.

## HTTP API

Everything the MCP proxy does is also available over HTTP. The agent API
listens on `127.0.0.1:9487` and `/run/sysrail/agent.sock`, and needs
`Authorization: Bearer <token>`.

```sh
T=$(cat ~/.config/sysrail/token)

# Tools this agent can reach, with input schemas. "id" is the capability ID used by /v1/execute.
curl -s -H "Authorization: Bearer $T" http://127.0.0.1:9487/v1/capabilities

# Run a capability
curl -s -H "Authorization: Bearer $T" http://127.0.0.1:9487/v1/execute \
  -d '{"capability": "service.status", "arguments": {"name": "nginx"}}'

curl -s -H "Authorization: Bearer $T" http://127.0.0.1:9487/v1/execute \
  -d '{"capability": "service.restart", "arguments": {"name": "nginx"}, "reason": "hung", "idempotency_key": "restart-nginx-1"}'

# Status of your own request, waiting up to 30 s
curl -s -H "Authorization: Bearer $T" "http://127.0.0.1:9487/v1/requests/req_…?wait=30"
```

`/v1/execute` returns `200` with `{"status": "success", "result": {...}}`, or
`202` with `{"status": "approval_required", "request_id": "...", "expires_at": "..."}`.
An optional `X-SysRail-Session` header labels calls in the audit log.

The admin API on the admin socket lists and decides requests, reads the audit
log, and streams all events. It does not run capabilities:

```sh
admin() { sudo curl -s --unix-socket /run/sysrail/admin.sock "$@"; }
admin "http://sysrail/v1/requests?status=pending"
admin "http://sysrail/v1/requests/req_…"
admin -X POST "http://sysrail/v1/requests/req_…/approve" -d '{"note": "ok"}'
admin -X POST "http://sysrail/v1/requests/req_…/deny" -d '{"note": "not now"}'
admin "http://sysrail/v1/audit?agent=opencode&limit=20"
```

## Errors

Errors always have this shape:

```json
{"error": {"code": "PERMISSION_DENIED", "message": "agent \"opencode\" is not permitted to use service.stop on nginx.service", "retryable": false}}
```

| Code | HTTP | Meaning | Retry? |
|---|---|---|---|
| `AUTHENTICATION_FAILED` | 401 | Missing or unknown token | No |
| `PERMISSION_DENIED` | 403 | Denied by policy, a protected unit, or polkit | No |
| `INVALID_ARGUMENT` | 400 | Bad arguments; the message says which | After fixing |
| `RESOURCE_NOT_FOUND` | 404 | Unknown unit, request or capability | No |
| `CONFLICT` | 409 | Request already decided or expired, idempotency key reused, job canceled | No |
| `TIMEOUT` | 504 | The operation exceeded its timeout | Yes |
| `PROVIDER_UNAVAILABLE` | 503 | systemd, journald or another source could not be reached | Yes |
| `EXECUTION_FAILED` | 500 | The operation failed, e.g. a service failed to start; check its logs | Depends |

Through MCP, errors come back as tool results with `isError: true` and the
same `error` object, so the agent can react to the code.

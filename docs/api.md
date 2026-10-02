# HTTP API reference

The daemon serves two HTTP APIs. The **agent API** is what `sysrail mcp` uses
and what custom integrations call. The **admin API** is for approving
requests and reading the audit log. For a task-oriented introduction with
examples, see [usage.md](usage.md#http-api).

## Conventions

| Listener | Serves | Authentication |
|---|---|---|
| `127.0.0.1:9487` (`server.http_listen`) | Agent API; admin API too if `admin.token_sha256` is set | Bearer token |
| `/run/sysrail/agent.sock` (`server.agent_socket`) | Agent API | Bearer token, plus membership of `sysrail-agents` |
| `/run/sysrail/admin.sock` (`server.admin_socket`) | Admin API | None beyond file permissions: mode 0600, owned by `sysrail`, so root and the daemon user |

- **Unix sockets.** With curl, use `--unix-socket <path>` and any host name,
  for example `curl --unix-socket /run/sysrail/admin.sock http://sysrail/v1/health`.
- **Bodies and timestamps.** Request and response bodies are JSON, and
  request bodies are limited to 1 MiB. Unknown fields in request bodies are
  rejected. Timestamps are RFC 3339.
- **Versioning.** All paths start with `/v1`. New fields may be added to
  responses, so clients should ignore fields they don't know.
- **Unknown paths and methods** return `404` with error code
  `RESOURCE_NOT_FOUND`.

### Authentication

Agent API requests need `Authorization: Bearer <token>`. A missing or unknown
token returns `401 AUTHENTICATION_FAILED`. Only `/v1/health` is public.

On the TCP listener, a request bearing the admin token (configured as
`admin.token_sha256`) goes to the admin API, and any other request goes to the
agent API.

### Optional headers

| Header | API | Meaning |
|---|---|---|
| `X-SysRail-Session` | Agent | Free-form session label recorded in the audit log. 1–64 characters from `A-Z a-z 0-9 _ . : -`; anything else is rejected with `400`. |
| `X-SysRail-Actor` | Admin | Claimed name of the approver, e.g. the user behind `sudo`. It's appended to the identity taken from the socket's peer credentials, such as `uid=0(root) via alice`. It's informational only. |

### Errors

Every error response has a JSON body:

```json
{"error": {"code": "PERMISSION_DENIED", "message": "agent \"opencode\" is not permitted to use service.stop on nginx.service", "retryable": false}}
```

| Field | Type | Meaning |
|---|---|---|
| `code` | string | One of the codes below |
| `message` | string | Human-readable explanation, with secrets redacted |
| `retryable` | bool | Whether repeating the same call may succeed |
| `details` | object, optional | Extra context, e.g. `request_id`, or `active_state` and `sub_state` when a service change fails |

| Code | HTTP | Meaning |
|---|---|---|
| `INVALID_ARGUMENT` | 400 | Bad request body, arguments, header or query parameter |
| `AUTHENTICATION_FAILED` | 401 | Missing or unknown token |
| `PERMISSION_DENIED` | 403 | Denied by policy, a protected unit, or polkit |
| `RESOURCE_NOT_FOUND` | 404 | Unknown capability, unit, request or path |
| `CONFLICT` | 409 | Request already decided or expired, idempotency key reused, systemd job canceled |
| `EXECUTION_FAILED` | 500 | The operation failed. Also returned with `retryable: true` when the audit log or request store is unavailable. |
| `PROVIDER_UNAVAILABLE` | 503 | A data source (systemd, journald, `/proc`) could not be reached; retryable |
| `TIMEOUT` | 504 | The operation exceeded its timeout; retryable |

## Agent API

### GET /v1/health

No authentication.

```json
{"status": "ok", "version": "86de99a"}
```

### GET /v1/capabilities

Returns the capabilities this agent can reach under the current policy. A
capability is omitted when the policy would deny it on every resource.

```json
{
  "agent": "opencode",
  "capabilities": [
    {
      "id": "service.restart",
      "tool": "service_restart",
      "description": "Restart a systemd service and report its resulting state.",
      "risk": "low",
      "mutating": true,
      "permission": "service.restart",
      "resource_kind": "service",
      "impact": "Stops and starts the service again; its clients see a brief interruption.",
      "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "reason": {"type": "string"}, "idempotency_key": {"type": "string"}}, "required": ["name"], "additionalProperties": false}
    }
  ]
}
```

See [Capability](#capability) for the fields. For mutating capabilities,
`input_schema` also lists the reserved `reason` and `idempotency_key`
arguments. `/v1/execute` takes those as top-level fields, not inside
`arguments`.

### POST /v1/execute

Runs a capability.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `capability` | string | yes | Capability ID, e.g. `service.restart`. This is the ID, not the tool name. |
| `arguments` | object | no | Arguments matching the capability's input schema; omitted means `{}` |
| `reason` | string | no | Up to 500 characters, shown to the approver |
| `idempotency_key` | string | no | Up to 128 printable ASCII characters without spaces |

```json
{"capability": "service.restart", "arguments": {"name": "nginx"}, "reason": "port 80 is free again", "idempotency_key": "restart-nginx-1"}
```

Responses carry an [Outcome](#outcome):

| HTTP | `status` | Meaning |
|---|---|---|
| 200 | `success` | Finished; `result` holds the capability result. Allowed mutations also carry `request_id`. |
| 202 | `approval_required` | Waiting for a human; `request_id` and `expires_at` are set |
| 202 | `in_progress` | An idempotent retry of a request that is approved and still running |
| 4xx/5xx | — | [Error](#errors) |

```json
{"status": "approval_required", "request_id": "req_01M3YQHXHVNE03F458XMJQ3ANN", "expires_at": "2026-10-02T18:50:58Z"}
```

```json
{"status": "success", "request_id": "req_01M3YQJ7V0K2Q9C8C3A1N6T2ZB",
 "result": {"unit": "nginx.service", "action": "restart", "job_result": "done", "active_state": "active", "sub_state": "running", "main_pid": 4242}}
```

Repeating a call with an `idempotency_key` the agent has already used, for
the same capability and arguments, returns the original request's current
state and never runs it twice:

| Original request is | Response |
|---|---|
| pending | `202 approval_required` (same `request_id`) |
| approved, still running | `202 in_progress` |
| executed | `200 success` with the stored result |
| failed | The stored error |
| denied | `403 PERMISSION_DENIED`, `details.request_id` |
| expired | `409 CONFLICT`, `details.request_id` |

Reusing the key for a different capability or different arguments returns
`409 CONFLICT`.

### GET /v1/requests/{id}

Returns the agent's own request as a [Request view](#request-view). This is
the HTTP form of the `request_get_status` tool.

| Query | Meaning |
|---|---|
| `wait` | Wait up to this many seconds (0–30) while the request is pending or running |

A request that belongs to another agent returns `404`, exactly like a request
that doesn't exist.

### GET /v1/events

Server-Sent Events stream. See [Events](#events).

The agent receives:
- events about its own requests;
- host events about resources it may read. For example, a `service.failed`
  event for `nginx.service` arrives only if the policy allows `service.read`
  on `nginx.service`.

## Admin API

The admin API performs no authentication of its own: it's reachable only
through the admin socket, or over TCP with the admin token.

### GET /v1/health

Same as for agents.

### GET /v1/capabilities

All registered capabilities, regardless of policy: `{"capabilities": [...]}`.

### GET /v1/requests

Lists tracked requests, newest first. Pending requests that have passed their
deadline are expired first.

| Query | Meaning |
|---|---|
| `status` | `pending`, `approved`, `denied`, `expired`, `executed` or `failed` |
| `agent` | Only this agent's requests |
| `limit` | 1–1000, default 100 |

```json
{"requests": [{"request_id": "req_01M3...", "agent": "opencode", "capability": "service.restart", "status": "pending", ...}]}
```

### GET /v1/requests/{id}

A full [Request](#request).

### POST /v1/requests/{id}/approve

Approves a pending request and runs it. The response is the final
[Request](#request), returned after the capability has finished. That can
take up to the capability's timeout (60 seconds by default for changes).

| Field | Type | Meaning |
|---|---|---|
| `note` | string, optional | Up to 500 bytes. Recorded with the decision and visible to the agent. |

The body may be empty or `{}`. The response is `200` even if the change
itself failed: look at `status` (`executed` or `failed`) and `error`.

Before running, the daemon re-validates the stored arguments, checks they
match the `arguments_hash` of the original call, and re-evaluates the policy.
If the policy now denies the call, the request ends as `failed` with
`PERMISSION_DENIED`.

| Error | When |
|---|---|
| `404 RESOURCE_NOT_FOUND` | No such request |
| `409 CONFLICT` | The request isn't pending, has expired, or was decided concurrently |

### POST /v1/requests/{id}/deny

Rejects a pending request. Same body and errors as approve. Returns the
[Request](#request) with `status: denied`.

### GET /v1/audit

Reads the audit log.

| Query | Meaning |
|---|---|
| `agent` | Only this agent |
| `capability` | Only this capability ID |
| `request_id` | Only records of this request |
| `after_id` | Records with an ID greater than this, oldest first |
| `limit` | 1–1000, default 100 |

Without `after_id`, the response holds the newest `limit` records, oldest
first. With `after_id`, it holds up to `limit` records that follow that ID.
To read the whole log, start with `after_id=0` and repeat with the last ID
you received until the list is empty.

```json
{"records": [{"id": 11, "timestamp": "...", "event": "request", "agent": "opencode", "capability": "service.restart", ...}]}
```

### GET /v1/events

All events, unfiltered. See [Events](#events).

## Events

`GET /v1/events` on either API streams `text/event-stream`:

| Parameter | Meaning |
|---|---|
| `types` (query) | Comma-separated event types to receive; default all |
| `since` (query) or `Last-Event-ID` (header) | Resume after this event ID |

Each event is one SSE frame. A comment line (`: keepalive`) is sent every
25 seconds.

```text
id: 6
event: service.failed
data: {"id":6,"time":"2026-10-02T16:42:57Z","type":"service.failed","source":"systemd","resource_kind":"service","resource":"nginx.service","data":{"active_state":"failed","previous_state":"active","sub_state":"failed"}}
```

The daemon keeps the last 1024 events in memory. Events older than that, or
from before a daemon restart, can't be replayed.

## Objects

### Capability

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Capability ID used with `/v1/execute`, e.g. `service.restart` |
| `tool` | string | MCP tool name, e.g. `service_restart` |
| `description` | string | What it does |
| `risk` | string | `read`, `low`, `medium`, `high` or `critical` |
| `mutating` | bool | Whether it changes the system |
| `permission` | string, optional | Policy permission it requires; absent for `request.status` |
| `resource_kind` | string, optional | `service` for capabilities that policy can scope to individual services |
| `impact` | string, optional | Side effects, shown to approvers (mutating capabilities only) |
| `input_schema` | object | JSON Schema of the arguments |

### Outcome

| Field | Type | Meaning |
|---|---|---|
| `status` | string | `success`, `approval_required` or `in_progress` |
| `request_id` | string, optional | Set for tracked requests: every mutation, and every call that needs approval |
| `expires_at` | time, optional | When a pending request expires |
| `result` | object, optional | Capability result (see [Capability results](#capability-results)), when `status` is `success` |

### Request

The admin view of a tracked request. Every mutation and every call that needs
approval is tracked.

| Field | Type | Meaning |
|---|---|---|
| `request_id` | string | `req_` followed by a ULID |
| `agent` | string | Agent that made the call |
| `session` | string, optional | Session label at the time of the call |
| `capability` | string | Capability ID |
| `resource` | string, optional | Normalized target, e.g. `nginx.service` |
| `arguments` | object | Normalized arguments that will be (or were) executed |
| `arguments_hash` | string | SHA-256 of capability ID and arguments |
| `reason` | string, optional | The agent's reason. Unverified. |
| `risk` | string | Risk level of the capability |
| `status` | string | See the lifecycle below |
| `policy_rule` | string, optional | The policy rule that decided the call |
| `idempotency_key` | string, optional | The agent's key, if any |
| `created_at` | time | |
| `expires_at` | time, optional | Deadline for a decision (requests that needed approval) |
| `decided_at`, `decided_by`, `decision_note` | optional | Who decided and when. `decided_by` is `policy` for allowed calls, the approver's identity, or `system` for expiry. |
| `completed_at` | time, optional | When execution finished |
| `result` | object, optional | Result after execution, secrets redacted |
| `error` | [Error](#errors), optional | Error after a failed execution |

Lifecycle:

```text
pending ──approve──▶ approved ──▶ executed | failed
   ├──deny──▶ denied
   └──deadline──▶ expired
```

Mutations that the policy allows outright start in `approved`, with
`decided_by: policy`.

### Request view

The agent view, returned by `GET /v1/requests/{id}` and `request_get_status`.
It contains `request_id`, `status`, `capability`, `resource`, `created_at`,
`expires_at`, `decided_at`, `decision_note`, `completed_at`, `result` and
`error`, with the same meaning as in [Request](#request). It omits the
arguments, the approver's identity and the policy rule.

### Audit record

| Field | Type | Meaning |
|---|---|---|
| `id` | int | Increasing record ID |
| `timestamp` | time | When the record was written |
| `event` | string | `request` (before anything runs), `result` (after a call ran), `approval` (decision or expiry) or `retention` (old records were archived and removed) |
| `agent`, `session` | string, optional | Caller |
| `capability`, `resource` | string, optional | What was called, on what |
| `arguments` | object, optional | Normalized arguments with secrets redacted (`request` records only) |
| `arguments_hash` | string, optional | SHA-256 of the unredacted arguments |
| `policy_decision`, `policy_rule` | string, optional | `allow`, `ask` or `deny`, and the rule that matched |
| `request_id` | string, optional | Tracked request, if any |
| `result` | string | `started`, `success`, `error`, `denied`, `invalid`, `approval_required`, `duplicate`, `approved`, `rejected`, `expired` or `pruned` |
| `error_code`, `error_message` | string, optional | For errors and refusals |
| `duration_ms` | int, optional | Execution time (`result` records) |
| `actor` | string, optional | Approver identity (`approval` and approved `result` records); `system` for expiry and retention |
| `note` | string, optional | Explanation on system records, e.g. what a `retention` record removed and where it was archived |

### Event

| Field | Type | Meaning |
|---|---|---|
| `id` | int | Increasing event ID, used to resume |
| `time` | time | |
| `type` | string | See below |
| `source` | string | `core` or `systemd` |
| `agent` | string, optional | Owner of a request event |
| `resource_kind`, `resource` | string, optional | What the event is about |
| `data` | object, optional | Event details |

| Type | `data` |
|---|---|
| `request.pending`, `request.approved`, `request.denied`, `request.expired`, `request.executed`, `request.failed` | `request_id`, `capability`, `status` |
| `service.failed`, `service.recovered` | `active_state`, `sub_state`, and `previous_state` when known |

## Notification webhook payload

Webhooks configured under `notifications.webhooks` receive a `POST` with
`Content-Type: application/json`. Any status other than 2xx counts as a
failure. HTTP 429 and 5xx are retried. Redirects are not followed.

```json
{
  "type": "request.pending",
  "title": "SysRail: approval needed on web1",
  "text": "opencode requests service.restart on nginx.service (risk: low).\nImpact: ...\n\nApprove: sudo sysrail approvals approve req_01M3...\nDeny:    sudo sysrail approvals deny req_01M3...",
  "priority": "high",
  "host": "web1",
  "event": {"id": 12, "time": "2026-10-02T19:00:00Z", "type": "request.pending", "source": "core", "agent": "opencode",
            "resource_kind": "service", "resource": "nginx.service",
            "data": {"request_id": "req_01M3...", "capability": "service.restart", "status": "pending"}},
  "request": {"request_id": "req_01M3...", "agent": "opencode", "capability": "service.restart",
              "resource": "nginx.service", "risk": "low", "status": "pending", "reason": "port 80 is free again",
              "impact": "Stops and starts the service again; its clients see a brief interruption.",
              "expires_at": "2026-10-02T19:15:00Z"}
}
```

| Field | Type | Meaning |
|---|---|---|
| `type` | string | Event type, or `test` for `sysrail notify test` |
| `title`, `text` | string | The rendered message, as sent to the other channels |
| `priority` | string | `high` for pending requests, failures and denials; otherwise `default` |
| `host` | string | Host name of the server |
| `event` | [Event](#event) | The event itself |
| `request` | object, optional | For request events. Has `request_id`, `agent`, `capability`, `resource`, `risk`, `status`, `reason` (from the agent, unverified, cleaned and redacted), `impact` (from SysRail), `expires_at`, `decided_by`, `decision_note`, `error_code` and `error_message` (each optional except the first, `agent`, `capability` and `status`). |

## Capability results

Results are JSON objects. Byte counts are integers and percentages have one
decimal place. Fields marked optional are omitted when unknown.

### system.status

`hostname`, `os` (`name`, `version`, `id`, `pretty_name`), `kernel`, `arch`,
`uptime_seconds`, `boot_time`, `load_average` (`1m`, `5m`, `15m`), `cpu_count`,
`memory` (`total_bytes`, `available_bytes`, `used_percent`), `processes`
(`running`, `total`).

### system.cpu

`model`, `logical_cpus`, `load_average`, `usage_percent`,
`per_cpu_usage_percent` (array, only with `per_cpu: true`), `frequency`
(`min_mhz`, `max_mhz`, `avg_mhz`; optional), `sample_ms`.

### system.memory

`total_bytes`, `available_bytes`, `used_bytes` (total minus available),
`used_percent`, `free_bytes`, `buffers_bytes`, `cached_bytes`, `shared_bytes`,
`swap` (`total_bytes`, `free_bytes`, `used_bytes`, `used_percent`), `note`.

### system.gpu

`available` (bool), `gpus`, and `errors` (array of strings, optional, e.g.
when `nvidia-smi` fails). Each GPU has `id` (`nvidia:<index>` or
`drm:<card>`), `vendor`, `name`, `source` (`nvidia-smi` or `sysfs`), and
optionally `driver`, `driver_version`, `uuid`, `pci_id`, `memory_total_bytes`,
`memory_used_bytes`, `memory_used_percent`, `utilization_percent`,
`temperature_c` and `power_watts`.

### storage.status

`filesystems`, `warnings` (array of strings), and `thresholds_percent`
(`warning`: 90, `critical`: 95). Each filesystem has `mount_point`, `device`,
`fstype`, `read_only`, `total_bytes`, `used_bytes`, `available_bytes`,
`used_percent`, optionally `inodes_total`, `inodes_used` and
`inodes_used_percent`, and `status` (`ok`, `warning`, `critical`, or
`unknown` with `error`).

### storage.mounts

`mounts`, `fstab_not_mounted`, and `hidden_pseudo_mounts` (optional). Each
mount has `mount_point`, `source`, `fstype`, `read_only`, `options` and
`device` (major:minor). Each `fstab_not_mounted` entry has `spec`,
`mount_point`, `fstype` and `options`.

### network.connections

`connections`, `total` and `truncated`. Each connection has `protocol`
(`tcp`, `tcp6`, `udp`, `udp6`), `local_address`, `local_port`, `state`
(`listen`, `established`, `time_wait`, …) and `uid`, plus `remote_address` and
`remote_port` for connected sockets.

### service.list

`services`, `total`, `truncated` and `note`. Each service has `name`,
`description`, `load_state`, `active_state` and `sub_state`.

### service.status

`name`, `description`, `load_state`, `active_state`, `sub_state`, `healthy`
(true when `active_state` is `active`), `restarts`, `exec_main_status`, and
optionally `unit_file_state`, `main_pid`, `result`, `memory_bytes`,
`state_changed_at`, `active_since`, `inactive_since` and `unit_file`.

### service.logs

`unit`, `entries`, `count` and `truncated`. Each entry has `time`, `message`,
and optionally `priority` (`emerg` … `debug`), `identifier` and `pid`.
Entries are oldest first, capped at 256 KiB of message text, and keep the
newest entries when the cap is reached.

### service.start, service.restart, service.stop

`unit`, `action`, `job_result` (systemd's job result, normally `done`), and
the resulting `active_state`, `sub_state` and `main_pid` (optional). A job
that does not end in `done` returns an error instead: `TIMEOUT`, `CONFLICT`
(canceled) or `EXECUTION_FAILED`.

### request.status

A [Request view](#request-view).

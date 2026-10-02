# Installing SysRail

This guide covers installing, configuring, upgrading and removing SysRail on
a Linux server. For day-to-day use, see [usage.md](usage.md).

## Requirements

- Linux on amd64 with systemd and journald.
- polkit with JavaScript rules (polkit 0.106 or newer; Ubuntu 24.04 ships
  polkit 124).
- Root access (sudo) for installation.
- Optional: `nvidia-smi` for NVIDIA GPU details. Other GPUs are read from sysfs.

To build you need `git`, `make` and Go 1.26 or newer. An older Go (1.21+) also
works: it downloads the toolchain pinned in `go.mod`. The build has no cgo
dependencies and produces a single static binary.

## Option 1: build and install on the server

```sh
sudo apt install -y git make          # Debian/Ubuntu
sudo snap install go --classic        # or install Go from https://go.dev/dl/
git clone https://github.com/w512/SysRail.git
cd SysRail
make build-linux                      # build/linux-amd64/sysrail
sudo ./deploy/install.sh build/linux-amd64/sysrail
```

## Option 2: build elsewhere and copy to the server

This keeps a Go toolchain off the server. The build works on macOS as well as
on Linux.

```sh
git clone https://github.com/w512/SysRail.git
cd SysRail
make build-linux                      # build/linux-amd64/sysrail
ssh server mkdir -p /tmp/sysrail
scp -r build/linux-amd64/sysrail deploy server:/tmp/sysrail/
ssh -t server 'cd /tmp/sysrail && sudo ./deploy/install.sh ./sysrail'
```

## What install.sh does

On a first install, `install.sh`:

1. Copies the binary to `/usr/local/bin/sysrail`.
2. Creates the `sysrail` system user (no login shell) and the `sysrail-agents`
   group.
3. Writes `/etc/sysrail/config.yaml` and `/etc/sysrail/policy.yaml` from the
   examples in `deploy/`. It also generates a token for an agent called
   `opencode` and stores only its SHA-256 in the config.
4. Installs the polkit rule `/etc/polkit-1/rules.d/50-sysrail.rules`. Out of
   the box it allows no service changes.
5. Checks the configuration and policy, installs and starts `sysrail.service`,
   and waits until the daemon is listening.

It prints the agent token once:

```text
SysRail 86de99a is running.

Agent token for "opencode" (shown once; store it in the agent's MCP config):

  sysrail_4fQ...
```

Save the token now; it cannot be recovered. If you lose it, create a new one
(see [Adding agents](#adding-agents)).

Re-running `install.sh` never overwrites `config.yaml`, `policy.yaml` or the
polkit rule.

### Installed files

| Path | Purpose |
|---|---|
| `/usr/local/bin/sysrail` | Daemon, MCP proxy and admin CLI (one binary) |
| `/etc/systemd/system/sysrail.service` | Sandboxed service unit |
| `/etc/sysrail/config.yaml` | Daemon configuration (root:sysrail, 0640) |
| `/etc/sysrail/policy.yaml` | Policy (root:sysrail, 0640) |
| `/etc/polkit-1/rules.d/50-sysrail.rules` | Which services the daemon may manage |
| `/var/lib/sysrail/sysrail.db` | Audit log and requests (SQLite, 0600) |
| `/run/sysrail/agent.sock` | Agent API (group `sysrail-agents`, 0660) |
| `/run/sysrail/admin.sock` | Admin API (owner only, 0600) |

## Configure after installing

### 1. Policy

Edit `/etc/sysrail/policy.yaml` to decide what each agent may do. The default
lets `opencode` read everything, ask before starting or restarting services,
and never stop them. Policy syntax and examples are in
[usage.md](usage.md#writing-a-policy).

Check the policy and apply it:

```sh
sudo sysrail policy check     # validates and prints each agent's effective grants
sudo systemctl reload sysrail # applies policy.yaml without a restart
```

If the new policy is invalid, the reload is rejected, the daemon keeps the
previous policy, and the error goes to `journalctl -u sysrail`.

### 2. polkit rule

SysRail starts, stops and restarts services through systemd over D-Bus as the
unprivileged `sysrail` user. polkit decides which units that user may touch.
This is a second boundary, independent of the SysRail policy, so keep it at
least as narrow.

Add the services you want managed to `allowed` in
`/etc/polkit-1/rules.d/50-sysrail.rules`:

```js
    var allowed = [
        /^nginx\.service$/,
        /^app-.*\.service$/,
    ];
```

polkit picks up the change automatically. A service that the policy allows
but polkit does not fails with `PERMISSION_DENIED` ("check the sysrail polkit
rule").

### 3. Agent users

Agents connect through `/run/sysrail/agent.sock`, which only members of
`sysrail-agents` can open. Add the users that run agents:

```sh
sudo usermod -aG sysrail-agents alice
```

The user must log out and back in (or run `newgrp sysrail-agents`) before the
new group applies. Group membership alone grants nothing: the agent still
needs a valid token.

Then connect the agent, as described in
[usage.md](usage.md#connecting-an-agent).

## Adding agents

Each agent gets its own token, so policies and audit records can tell agents
apart.

1. Create a token:

   ```sh
   sysrail token create
   ```

   ```text
   token:        sysrail_Zx1...
   token_sha256: 3b7c...
   ```

2. Add the hash to `/etc/sysrail/config.yaml`. Agent names use lowercase
   letters, digits, `-` and `_`:

   ```yaml
   agents:
     opencode:
       token_sha256: "..."
     backup-bot:
       token_sha256: "3b7c..."
   ```

3. Give the agent rules in `policy.yaml`. An agent without rules is denied
   everything.

4. Restart the daemon, because `reload` only re-reads the policy:

   ```sh
   sudo sysrail policy check && sudo systemctl restart sysrail
   ```

To revoke an agent, remove it from both files and restart.

## Configuration reference

`/etc/sysrail/config.yaml`. Unknown keys are rejected. Relative paths are
resolved against the file's directory.

| Key | Default | Notes |
|---|---|---|
| `server.http_listen` | `127.0.0.1:9487` | Agent HTTP API. `""` disables it. |
| `server.allow_remote` | `false` | Must be `true` to bind a non-loopback address. There is no TLS; prefer an SSH tunnel. |
| `server.agent_socket` | `/run/sysrail/agent.sock` | Agent API over a Unix socket. `""` disables it. |
| `server.agent_socket_group` | none (`sysrail-agents` in the example) | Group allowed to connect (socket mode 0660). |
| `server.admin_socket` | `/run/sysrail/admin.sock` | Admin API, mode 0600. Required. |
| `database` | `/var/lib/sysrail/sysrail.db` | SQLite file for the audit log and requests. |
| `policy_file` | `/etc/sysrail/policy.yaml` | |
| `approvals.ttl` | `15m` | How long a request waits for approval (1m to 24h). |
| `limits.calls_per_minute` | `120` | Sustained calls per agent across all tools. `0` = unlimited. See [Limits](#limits). |
| `limits.burst` | `30` | Calls an agent may make back to back. |
| `limits.max_pending` | `10` | Requests per agent waiting for approval at once. `0` = unlimited. |
| `audit.retention_days` | `90` | Days to keep audit records and finished requests (checked at startup and hourly). `0` keeps everything. See [Audit retention](#audit-retention). |
| `audit.archive` | `true` | Write removed records to compressed archives first. |
| `audit.archive_dir` | `archive` next to the database | Where archives are written. |
| `timeouts.read` | `10s` | Default timeout for read tools (at most 10m). |
| `timeouts.mutating` | `60s` | Default timeout for service changes (at most 10m). |
| `admin.token_sha256` | none | Optional. Allows the admin API over HTTP for the holder of this token. |
| `agents.<name>.token_sha256` | — | One entry per agent. |
| `agents.<name>.limits` | inherited | Overrides any of `calls_per_minute`, `burst`, `max_pending` for this agent. |
| `providers.linux.enabled` | `true` | System, CPU, memory, GPU, storage, network tools. |
| `providers.systemd.enabled` | `true` | Service tools. |
| `providers.systemd.protected_units` | built-in list | Globs of units that can never be changed. The default covers dbus, `systemd-*`, polkit, ssh, sshd, `user@*` and `getty@*`. `sysrail.service` is always protected. |
| `notifications.ntfy` | none | List of `url` (topic URL), `token`, `events`. See [Notifications](#notifications). |
| `notifications.telegram` | none | List of `bot_token`, `chat_id`, `api_url`, `events`. |
| `notifications.email` | none | List of `smtp_host`, `smtp_port` (587, or 465 with implicit TLS), `tls` (`starttls`, `implicit`, `none`), `username`, `password`, `from`, `to`, `events`. |
| `notifications.webhooks` | none | List of `url`, `headers`, `events`. |
| `log.level` | `info` | `debug`, `info`, `warn` or `error`. Logs go to the journal. |

Changes to `config.yaml` take effect after `sudo systemctl restart sysrail`.

## Verify the installation

```sh
systemctl status sysrail                 # active (running)
curl -s http://127.0.0.1:9487/v1/health  # {"status":"ok","version":"..."}
sudo sysrail policy check                # effective grants per agent
sudo sysrail audit                       # recent calls (empty at first)
```

## Operations

### Logs and health

The daemon logs JSON lines to the journal:

```sh
journalctl -u sysrail -f -o cat
```

Set `log.level: debug` in the config to also log every HTTP request. systemd
restarts the daemon if it crashes (`Restart=on-failure`). For external
monitoring, check `systemctl is-active sysrail` or `GET /v1/health`.

### Notifications

SysRail announces requests that need approval through ntfy, Telegram, email
and webhooks. It can also announce other events. Without notifications, a
request just waits until someone runs `sudo sysrail approvals list`, and
expires after `approvals.ttl`.

Configure channels under `notifications`, restart, and send a test message:

```yaml
notifications:
  ntfy:
    - url: https://ntfy.sh/sysrail-3f9c2a7d8e     # a long, unguessable topic
  telegram:
    - bot_token: "123456789:AA..."
      chat_id: "123456789"
  email:
    - smtp_host: smtp.example.com
      username: sysrail@example.com
      password: "..."
      from: SysRail <sysrail@example.com>
      to: [admin@example.com]
  webhooks:
    - url: https://automation.example.com/hooks/sysrail
      headers: {Authorization: "Bearer ..."}
```

```sh
sudo systemctl restart sysrail
sudo sysrail notify test        # one test message per channel; reports failures
```

A request that needs approval is announced like this:

```text
SysRail: approval needed on web1

opencode requests service.restart on nginx.service (risk: low).
Impact: Stops and starts the service again; its clients see a brief interruption.
Reason (from the agent, unverified): port 80 is free again
Expires: 2026-10-02 21:15:00 CEST

Approve: sudo sysrail approvals approve req_01M3YQHXHVNE03F458XMJQ3ANN
Deny:    sudo sysrail approvals deny req_01M3YQHXHVNE03F458XMJQ3ANN
```

**Events.** Each channel takes an `events` list. The default is
`[request.pending]`. The others are `request.approved`, `request.denied`,
`request.expired`, `request.executed`, `request.failed`, `service.failed` and
`service.recovered`, for example `events: [request.pending, service.failed]`.

**Channels:**

- **ntfy.** Anyone who knows the name of a topic on the public ntfy.sh can
  read it. Use a long random topic, an access token (`token`) or a
  self-hosted server. Pending requests and failures are sent with high
  priority.
- **Telegram.** Create a bot with @BotFather and send it a message. Your chat
  ID is then shown by `https://api.telegram.org/bot<token>/getUpdates`. Group
  chat IDs are negative.
- **Email.** STARTTLS on port 587 is the default. Use `tls: implicit` for
  port 465. `tls: none` is allowed only without a username and password, for
  example for a local relay.
- **Webhooks** receive a JSON message, described in
  [api.md](api.md#notification-webhook-payload).

**Delivery:**

- Delivery runs in the background and never slows down agents.
- Network errors, HTTP 429 and 5xx, and temporary SMTP errors are retried
  after 2, 10 and 30 seconds, without delaying newer messages.
- A message that still fails is logged as `notification failed` in
  `journalctl -u sysrail`.

**Approval still happens only on the server.** Messages contain no links or
buttons that approve anything.

**Messages leave the host.** They contain the host name, agent, capability,
resource and the agent's reason. Bot tokens, SMTP passwords and ntfy tokens
are stored in `config.yaml`, which only root and the `sysrail` group can read.

### Limits

Each agent has a call budget, so one misbehaving agent cannot flood the
daemon, the approval queue or the audit log:

- **Call rate.** By default an agent may make 30 calls back to back, and
  then about 2 per second (`limits.burst: 30`,
  `limits.calls_per_minute: 120`). Every tool call counts, including
  `request_get_status` polls. Calls over the limit fail with `RATE_LIMITED`
  and a `retry_after_seconds` hint.
- **Pending requests.** An agent can have at most 10 requests waiting for
  approval (`limits.max_pending`). Further requests that need approval fail
  with `RATE_LIMITED` until you approve or deny some, or they expire.
  Retrying an existing request with its `idempotency_key` doesn't count.

Raise or remove limits for a trusted automation agent, for example:

```yaml
agents:
  monitor:
    token_sha256: "..."
    limits:
      calls_per_minute: 600
      burst: 100
```

`0` disables a limit. Changes need a restart.

Rejected calls are audited without letting a flood fill the audit log. The
first rejection is recorded in full. Further rejections of that agent within
10 seconds are only counted, and a `rate_limit` summary records how many
there were.

### Restarts and pending requests

- **Requests survive restarts.** They are stored in the database and keep
  their original deadline. Agents can keep polling `request_get_status`, and
  you can approve them after the restart.
- **Stopping during a change.** When the daemon stops, it waits up to
  15 seconds for calls that are still running. A change still running after
  that is left in the `approved` state with no result. Check the service
  itself and the audit log.
- **Event history is in memory** and starts empty after a restart.
- **Policy reloads don't touch pending requests.** The policy is checked
  again when a request is approved.

### Rotating an agent token

1. Create a new token with `sysrail token create`.
2. Replace the agent's `token_sha256` in `/etc/sysrail/config.yaml`.
3. Restart: `sudo sysrail policy check && sudo systemctl restart sysrail`.
   The old token stops working at this point.
4. Put the new token in the agent's token file.

The agent's identity is its name, not its token. Its pending requests and
audit history carry over.

### Backing up

Back up `/etc/sysrail/`, `/etc/polkit-1/rules.d/50-sysrail.rules`, the
database `/var/lib/sysrail/sysrail.db` and the audit archives in
`/var/lib/sysrail/archive/`.

With the `sqlite3` tool installed (`sudo apt install sqlite3`), the database
can be copied while the daemon runs:

```sh
sudo sqlite3 /var/lib/sysrail/sysrail.db ".backup '/var/backups/sysrail-$(date +%F).db'"
```

Without it, stop the daemon briefly. After a clean stop, the database is a
single self-contained file:

```sh
sudo systemctl stop sysrail
sudo cp -a /var/lib/sysrail/sysrail.db /var/backups/sysrail-$(date +%F).db
sudo systemctl start sysrail
```

To restore a backup:

```sh
sudo systemctl stop sysrail
sudo install -m 0600 -o sysrail -g sysrail /var/backups/sysrail-2026-10-01.db /var/lib/sysrail/sysrail.db
sudo rm -f /var/lib/sysrail/sysrail.db-wal /var/lib/sysrail/sysrail.db-shm
sudo systemctl start sysrail
```

### Exporting the audit log

`sudo sysrail audit --json --limit 1000` prints the newest 1000 records. For
a complete export, page through `GET /v1/audit` with `after_id`, as described
in [api.md](api.md#get-v1audit). Alternatively, read the table directly; this
is safe while the daemon runs:

```sh
sudo sqlite3 -readonly -json /var/lib/sysrail/sysrail.db \
  "SELECT * FROM audit_log WHERE id > 0 ORDER BY id" > sysrail-audit.json
```

Increase `id > 0` to the last exported ID for incremental exports. The
columns match the API fields, except that the time is in `ts`. Records older
than the retention period are no longer in the database: they are in the
archives. Export
regularly to another machine if you need an audit trail that root on this
host cannot alter.

### Audit retention

By default, audit records and finished requests older than 90 days are
removed, at startup and then every hour.

Before removal, they are written to compressed JSON Lines files in
`/var/lib/sysrail/archive`: one file per batch, mode 0600. The removal
itself is recorded as a `retention` record:

```text
$ sudo sysrail audit --limit 1
ID   TIME                 EVENT      AGENT  CAPABILITY  RESOURCE  DECISION  RESULT  DETAIL
812  2026-10-02 12:00:00  retention  -      -           -         -         pruned  removed 2450 audit records and 31 finished requests older than 2026-07-04T12:00:00Z; archived to /var/lib/sysrail/archive/audit-20261002T120000Z-001.jsonl.gz
```

To read an archive:

```sh
sudo zcat /var/lib/sysrail/archive/audit-*.jsonl.gz | head
```

Each line is either `{"type": "audit", "record": {...}}`, with the same fields
as `GET /v1/audit`, or `{"type": "request", "request": {...}}`, with the
arguments redacted.

**Settings:**

- `audit.retention_days` sets the period; `0` keeps everything.
- `audit.archive: false` deletes old records without writing archives.
- `audit.archive_dir` moves the archives elsewhere. The default location is
  inside the service's writable state directory; another path may need a
  `ReadWritePaths=` drop-in.
- Pending and running requests are never removed.
- SysRail never deletes the archives. Move them off the host or delete them
  according to your own rules.

**Size.** Every call adds two records of roughly 270 bytes each, so about
0.5 KB per call. SQLite reuses the space that retention frees, so the file
stops growing but does not shrink. To shrink it once, stop the daemon and run
`sudo sqlite3 /var/lib/sysrail/sysrail.db VACUUM`.

**Starting over.** To start a fresh database without waiting for retention,
stop the daemon, move `sysrail.db` away, and start it again. Requests still
pending stay in the old file.

## Upgrade

Build the new version and run `install.sh` again with the new binary (either
option above). It replaces the binary and the unit file, keeps your
configuration, policy, polkit rule and audit log, and restarts the daemon.

`install.sh` overwrites `/etc/systemd/system/sysrail.service`. Put local
changes in a drop-in so they survive upgrades:

```sh
sudo systemctl edit sysrail
```

## Uninstall

```sh
sudo ./deploy/uninstall.sh           # keeps /etc/sysrail and /var/lib/sysrail
sudo ./deploy/uninstall.sh --purge   # also deletes config, audit log, user and groups
```

## Troubleshooting

**Notifications don't arrive.** Run `sudo sysrail notify test`, which reports
the error for each channel. Common causes are a wrong chat ID or bot token, an
SMTP server that requires `tls: implicit`, and a firewall blocking outbound
connections. Delivery errors from the daemon appear as `notification failed`
in `journalctl -u sysrail`.

**The service does not start.** Look at `journalctl -u sysrail -n 50`. The
most common cause is an invalid configuration or policy: an unknown key, a
typo in a permission, or an agent in the policy that is missing from the
config. `sudo sysrail policy check` shows the exact error.

**`sysrail mcp: daemon at unix:///run/sysrail/agent.sock is not reachable`.**
The user is not in `sysrail-agents`, or has not logged in again since being
added. Check with `id`.

**`AUTHENTICATION_FAILED`.** The token does not match any `token_sha256` in
the config, or the daemon was not restarted after the config changed.

**A service change fails with `PERMISSION_DENIED` "check the sysrail polkit
rule".** The SysRail policy allowed it but the polkit rule did not. Add the
unit to `allowed` in `50-sysrail.rules`.

**A service change fails with `PERMISSION_DENIED` "... is a protected unit".**
The unit is in `providers.systemd.protected_units`. That is intentional for
dbus, systemd, polkit and ssh. `sysrail.service` can never be changed through
SysRail.

**`service_get_logs` returns nothing.** The daemon reads the journal through
the `systemd-journal` group set in the unit file. Check that the group exists
and that the unit still has `SupplementaryGroups=systemd-journal`.

**The GPU is missing from `system_get_gpu_status`.** For NVIDIA, check that
`nvidia-smi` works on the host and is on the default system `PATH` (for
example `/usr/bin`). Don't add `PrivateDevices=yes` to the unit: it hides
`/dev/nvidia*`.

**A call fails with "operation not permitted" after you customized the unit.**
The unit has a system-call filter. Find the blocked call with
`sudo journalctl -k | grep type=1326`; the `syscall=` field is the x86_64
syscall number.

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
| `timeouts.read` | `10s` | Default timeout for read tools (at most 10m). |
| `timeouts.mutating` | `60s` | Default timeout for service changes (at most 10m). |
| `admin.token_sha256` | none | Optional. Allows the admin API over HTTP for the holder of this token. |
| `agents.<name>.token_sha256` | — | One entry per agent. |
| `providers.linux.enabled` | `true` | System, CPU, memory, GPU, storage, network tools. |
| `providers.systemd.enabled` | `true` | Service tools. |
| `providers.systemd.protected_units` | built-in list | Globs of units that can never be changed. The default covers dbus, `systemd-*`, polkit, ssh, sshd, `user@*` and `getty@*`. `sysrail.service` is always protected. |
| `log.level` | `info` | `debug`, `info`, `warn` or `error`. Logs go to the journal. |

Changes to `config.yaml` take effect after `sudo systemctl restart sysrail`.

## Verify the installation

```sh
systemctl status sysrail                 # active (running)
curl -s http://127.0.0.1:9487/v1/health  # {"status":"ok","version":"..."}
sudo sysrail policy check                # effective grants per agent
sudo sysrail audit                       # recent calls (empty at first)
```

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

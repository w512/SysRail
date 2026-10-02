#!/usr/bin/env bash
# Installs or upgrades SysRail on a systemd-based Linux host.
#
#   sudo ./deploy/install.sh path/to/sysrail
#
# Existing /etc/sysrail/config.yaml, policy.yaml and the polkit rule are never
# overwritten. On first install an agent token for "opencode" is generated and
# printed once.
set -euo pipefail

BIN="${1:-./sysrail}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/sysrail
RULES=/etc/polkit-1/rules.d/50-sysrail.rules
PLACEHOLDER=0000000000000000000000000000000000000000000000000000000000000000

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: run as root" >&2
	exit 1
fi
if [ ! -x "$BIN" ]; then
	echo "install.sh: binary $BIN not found" >&2
	exit 1
fi
getent group systemd-journal >/dev/null || { echo "install.sh: group systemd-journal missing" >&2; exit 1; }

install -m 0755 "$BIN" /usr/local/bin/sysrail
getent group sysrail-agents >/dev/null || groupadd --system sysrail-agents
if ! id sysrail >/dev/null 2>&1; then
	useradd --system --user-group --no-create-home --home-dir /var/lib/sysrail \
		--shell /usr/sbin/nologin --comment "SysRail daemon" sysrail
fi

install -d -m 0750 -o root -g sysrail "$ETC"
new_token=""
if [ ! -f "$ETC/config.yaml" ]; then
	out="$(/usr/local/bin/sysrail token create)"
	new_token="$(awk '/^token:/{print $2}' <<<"$out")"
	hash="$(awk '/^token_sha256:/{print $2}' <<<"$out")"
	sed "s/$PLACEHOLDER/$hash/" "$DIR/config.example.yaml" >"$ETC/config.yaml"
	chown root:sysrail "$ETC/config.yaml"
	chmod 0640 "$ETC/config.yaml"
fi
if [ ! -f "$ETC/policy.yaml" ]; then
	install -m 0640 -o root -g sysrail "$DIR/policy.example.yaml" "$ETC/policy.yaml"
fi
if [ ! -f "$RULES" ]; then
	install -D -m 0644 "$DIR/50-sysrail.rules" "$RULES"
fi
install -m 0644 "$DIR/sysrail.service" /etc/systemd/system/sysrail.service

/usr/local/bin/sysrail policy check --config "$ETC/config.yaml" >/dev/null
systemctl daemon-reload
systemctl enable sysrail.service >/dev/null 2>&1
systemctl restart sysrail.service

# The unit is "active" as soon as the process starts; wait for the daemon to
# listen so the admin commands work right after this script returns.
admin_socket="$(awk '/^[[:space:]]*admin_socket:/{print $2}' "$ETC/config.yaml" | tr -d '"')"
admin_socket="${admin_socket:-/run/sysrail/admin.sock}"
for _ in $(seq 50); do
	[ -S "$admin_socket" ] && break
	sleep 0.1
done
if ! systemctl is-active --quiet sysrail.service || [ ! -S "$admin_socket" ]; then
	echo "install.sh: sysrail did not start; see: journalctl -u sysrail" >&2
	exit 1
fi

echo "SysRail $(/usr/local/bin/sysrail version | awk '{print $2}') is running."
if [ -n "$new_token" ]; then
	cat <<EOF

Agent token for "opencode" (shown once; store it in the agent's MCP config):

  $new_token

Next steps:
  1. Review $ETC/policy.yaml and $RULES (which services may be managed).
  2. Add agent users to the sysrail-agents group: usermod -aG sysrail-agents <user>
  3. Configure the agent's MCP server: command "sysrail", args ["mcp"],
     env SYSRAIL_TOKEN=<token>.
EOF
fi

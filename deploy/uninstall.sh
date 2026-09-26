#!/usr/bin/env bash
# Removes SysRail. With --purge, also deletes configuration, the audit
# database, and the sysrail user and groups.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh: run as root" >&2
	exit 1
fi

systemctl disable --now sysrail.service 2>/dev/null || true
rm -f /etc/systemd/system/sysrail.service /usr/local/bin/sysrail /etc/polkit-1/rules.d/50-sysrail.rules
systemctl daemon-reload

if [ "${1:-}" = "--purge" ]; then
	rm -rf /etc/sysrail /var/lib/sysrail /run/sysrail
	id sysrail >/dev/null 2>&1 && userdel sysrail
	getent group sysrail >/dev/null && groupdel sysrail
	getent group sysrail-agents >/dev/null && groupdel sysrail-agents
	echo "SysRail removed, including configuration and audit log."
else
	echo "SysRail removed. /etc/sysrail and /var/lib/sysrail were kept (use --purge to delete)."
fi

#!/usr/bin/env bash
# Removes everything scripts/deploy-remote.sh installed on the test host.
set -euo pipefail

HOST="${SYSRAIL_TEST_HOST:-sky@192.168.50.214}"

if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST" true 2>/dev/null; then
	echo "undeploy-remote: $HOST is unreachable. Is the test machine powered on?" >&2
	exit 2
fi

ssh "$HOST" "sudo -n bash -s" <<'EOF'
set -euo pipefail
systemctl stop 'sysrail-test-*.service' 2>/dev/null || true
rm -f /run/systemd/system/sysrail-test-*.service
systemctl reset-failed 'sysrail-test-*.service' 2>/dev/null || true
rm -rf /root/sysrail-e2e /tmp/sysrail-deploy
EOF
ssh "$HOST" "sudo -n bash -s -- --purge" <deploy/uninstall.sh
echo "test host cleaned"

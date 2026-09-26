#!/usr/bin/env bash
# Installs the current build on the Linux test host with the test overlay from
# deploy/test: test config and policy, a polkit rule limited to sysrail-test-*
# units, a runtime-only dummy service, and fresh agent tokens stored in
# /root/sysrail-e2e. Undo with scripts/undeploy-remote.sh.
set -euo pipefail

HOST="${SYSRAIL_TEST_HOST:-sky@192.168.50.214}"
STAGE_DIR=/tmp/sysrail-deploy

if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST" true 2>/dev/null; then
	echo "deploy-remote: $HOST is unreachable. Is the test machine powered on?" >&2
	exit 2
fi

make build-linux >/dev/null
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp build/linux-amd64/sysrail "$stage/"
cp -R deploy "$stage/"
COPYFILE_DISABLE=1 tar -C "$stage" --no-xattrs -czf - . |
	ssh "$HOST" "rm -rf $STAGE_DIR && mkdir -p $STAGE_DIR && tar -C $STAGE_DIR --warning=no-unknown-keyword -xzf -"

ssh "$HOST" "sudo -n bash -s" <<EOF
set -euo pipefail
cd $STAGE_DIR
./deploy/install.sh ./sysrail >/dev/null

install -d -m 0700 /root/sysrail-e2e
cfg=\$(cat deploy/test/config.yaml)
for agent in e2e e2e-readonly; do
	out=\$(/usr/local/bin/sysrail token create)
	awk '/^token:/{print \$2}' <<<"\$out" >/root/sysrail-e2e/\$agent.token
	hash=\$(awk '/^token_sha256:/{print \$2}' <<<"\$out")
	key=\$(echo "\$agent" | tr 'a-z-' 'A-Z_')_HASH
	cfg=\${cfg//@\${key}@/\$hash}
done
chmod 0600 /root/sysrail-e2e/*.token
printf '%s\n' "\$cfg" >/etc/sysrail/config.yaml
install -m 0640 -o root -g sysrail deploy/test/policy.yaml /etc/sysrail/policy.yaml
chown root:sysrail /etc/sysrail/config.yaml && chmod 0640 /etc/sysrail/config.yaml
install -m 0644 deploy/test/50-sysrail.rules /etc/polkit-1/rules.d/50-sysrail.rules
install -m 0644 deploy/test/sysrail-test-dummy.service /run/systemd/system/sysrail-test-dummy.service
systemctl daemon-reload
systemctl restart sysrail.service
for i in \$(seq 50); do [ -S /run/sysrail/agent.sock ] && break; sleep 0.1; done
systemctl is-active sysrail.service
EOF
echo "deployed to $HOST"

#!/usr/bin/env bash
# Cross-compiles test binaries on the dev machine and runs them on the Linux
# test host. No Go toolchain is needed on the host.
#
# Environment:
#   SYSRAIL_TEST_HOST  ssh destination (default: sky@192.168.50.214)
#   SYSRAIL_TEST_DIR   remote working directory (default: /tmp/sysrail-test)
#   TAGS               build tags (default: integration)
#   PKGS               packages to test (default: ./...)
#   SUDO               set to 0 to run tests without sudo (default: 1)
#   ARGS               extra test binary flags, e.g. "-test.run TestFoo"
set -euo pipefail

HOST="${SYSRAIL_TEST_HOST:-sky@192.168.50.214}"
REMOTE_DIR="${SYSRAIL_TEST_DIR:-/tmp/sysrail-test}"
TAGS="${TAGS:-integration}"
PKGS="${PKGS:-./...}"
SUDO="${SUDO:-1}"
ARGS="${ARGS:-}"
OUT="build/test"
MODULE="$(go list -m)"

if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST" true 2>/dev/null; then
	echo "test-remote: $HOST is unreachable. Is the test machine powered on?" >&2
	exit 2
fi

rm -rf "$OUT"
mkdir -p "$OUT"

built=()
for pkg in $(GOOS=linux GOARCH=amd64 go list -tags "$TAGS" $PKGS); do
	rel="${pkg#"$MODULE"}"
	rel="${rel#/}"
	[ -z "$rel" ] && rel="."
	dir="$OUT/$rel"
	mkdir -p "$dir"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags "$TAGS" -o "$dir/pkg.test" "$pkg" >/dev/null
	if [ -f "$dir/pkg.test" ]; then
		if [ -d "$rel/testdata" ]; then
			cp -R "$rel/testdata" "$dir/testdata"
		fi
		built+=("$rel")
	fi
done

if [ ${#built[@]} -eq 0 ]; then
	echo "test-remote: no test binaries were built" >&2
	exit 1
fi

COPYFILE_DISABLE=1 tar -C "$OUT" --no-xattrs -czf - . |
	ssh "$HOST" "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR' && tar -C '$REMOTE_DIR' --warning=no-unknown-keyword -xzf -"

runner=""
[ "$SUDO" = "1" ] && runner="sudo -n"

status=0
for rel in "${built[@]}"; do
	echo "=== $rel"
	if ! ssh "$HOST" "cd '$REMOTE_DIR/$rel' && $runner ./pkg.test $ARGS"; then
		status=1
	fi
done
exit $status

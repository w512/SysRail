//go:build linux

package systemd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runJournalctl runs journalctl with argv only (no shell) and a minimal,
// fixed environment.
func runJournalctl(ctx context.Context, path string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LANG=C.UTF-8", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=", "PAGER=cat"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("%w: %s", err, msg)
	}
	return out, nil
}

//go:build linux

package linux

import (
	"context"
	"os/exec"
	"syscall"
)

func statfs(path string) (FSUsage, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return FSUsage{}, err
	}
	bs := uint64(s.Bsize)
	return FSUsage{
		Total: s.Blocks * bs, Free: s.Bfree * bs, Available: s.Bavail * bs,
		Inodes: s.Files, InodesFree: s.Ffree,
	}, nil
}

// runCommand runs a helper with a minimal, fixed environment. Arguments are
// passed as argv; no shell is involved.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	return cmd.Output()
}

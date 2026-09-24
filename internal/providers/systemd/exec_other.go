//go:build !linux

package systemd

import (
	"context"
	"errors"
)

func runJournalctl(context.Context, string, []string) ([]byte, error) {
	return nil, errors.New("journalctl is only available on Linux")
}

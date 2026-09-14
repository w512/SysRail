//go:build !linux

package linux

import (
	"context"
	"errors"
)

var errNotLinux = errors.New("only supported on Linux")

func statfs(string) (FSUsage, error) { return FSUsage{}, errNotLinux }

func runCommand(context.Context, string, ...string) ([]byte, error) { return nil, errNotLinux }

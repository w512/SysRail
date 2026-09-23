//go:build !linux

package systemd

import (
	"context"

	"github.com/w512/SysRail/internal/core"
)

type unsupportedManager struct{}

// NewDBusManager returns a Manager that reports systemd as unavailable on
// non-Linux systems.
func NewDBusManager() Manager { return unsupportedManager{} }

func errUnsupported() error {
	return core.Errorf(core.CodeProviderUnavailable, "systemd is only available on Linux")
}

func (unsupportedManager) ListUnits(context.Context, []string, []string) ([]UnitStatus, error) {
	return nil, errUnsupported()
}

func (unsupportedManager) Properties(context.Context, string) (*UnitProperties, error) {
	return nil, errUnsupported()
}

func (unsupportedManager) Start(context.Context, string) (string, error) { return "", errUnsupported() }
func (unsupportedManager) Stop(context.Context, string) (string, error)  { return "", errUnsupported() }
func (unsupportedManager) Restart(context.Context, string) (string, error) {
	return "", errUnsupported()
}

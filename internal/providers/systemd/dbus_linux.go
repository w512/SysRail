//go:build linux

package systemd

import (
	"context"
	"errors"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"

	"github.com/w512/SysRail/internal/core"
)

// dbusManager talks to the system manager. It opens a connection per call so
// a restarted dbus or systemd never leaves it holding a dead connection.
type dbusManager struct{}

// NewDBusManager returns a Manager backed by the systemd D-Bus API. It does
// not connect until first use.
func NewDBusManager() Manager { return dbusManager{} }

func (dbusManager) conn(ctx context.Context) (*sddbus.Conn, error) {
	c, err := sddbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, core.Errorf(core.CodeProviderUnavailable, "connect to systemd: %v", err)
	}
	return c, nil
}

func (m dbusManager) ListUnits(ctx context.Context, states, patterns []string) ([]UnitStatus, error) {
	c, err := m.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	units, err := c.ListUnitsByPatternsContext(ctx, states, patterns)
	if err != nil {
		return nil, mapDBusError(err, "")
	}
	out := make([]UnitStatus, 0, len(units))
	for _, u := range units {
		out = append(out, UnitStatus{Name: u.Name, Description: u.Description, LoadState: u.LoadState,
			ActiveState: u.ActiveState, SubState: u.SubState})
	}
	return out, nil
}

func (m dbusManager) Properties(ctx context.Context, unit string) (*UnitProperties, error) {
	c, err := m.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	props, err := c.GetUnitPropertiesContext(ctx, unit)
	if err != nil {
		return nil, mapDBusError(err, unit)
	}
	p := &UnitProperties{
		Name:                   str(props["Id"]),
		Description:            str(props["Description"]),
		LoadState:              str(props["LoadState"]),
		ActiveState:            str(props["ActiveState"]),
		SubState:               str(props["SubState"]),
		UnitFileState:          str(props["UnitFileState"]),
		FragmentPath:           str(props["FragmentPath"]),
		StateChangeTimestamp:   u64(props["StateChangeTimestamp"]),
		ActiveEnterTimestamp:   u64(props["ActiveEnterTimestamp"]),
		InactiveEnterTimestamp: u64(props["InactiveEnterTimestamp"]),
	}
	if p.LoadState == "not-found" {
		return p, nil
	}
	svc, err := c.GetUnitTypePropertiesContext(ctx, unit, "Service")
	if err != nil {
		return nil, mapDBusError(err, unit)
	}
	p.MainPID, _ = svc["MainPID"].(uint32)
	p.NRestarts, _ = svc["NRestarts"].(uint32)
	p.ExecMainStatus, _ = svc["ExecMainStatus"].(int32)
	p.Result = str(svc["Result"])
	p.MemoryCurrent = u64(svc["MemoryCurrent"])
	return p, nil
}

type jobFunc func(c *sddbus.Conn, ctx context.Context, name, mode string, ch chan<- string) (int, error)

func (m dbusManager) job(ctx context.Context, unit string, fn jobFunc) (string, error) {
	c, err := m.conn(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	ch := make(chan string, 1)
	if _, err := fn(c, ctx, unit, "replace", ch); err != nil {
		return "", mapDBusError(err, unit)
	}
	select {
	case result := <-ch:
		return result, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (m dbusManager) Start(ctx context.Context, unit string) (string, error) {
	return m.job(ctx, unit, (*sddbus.Conn).StartUnitContext)
}

func (m dbusManager) Stop(ctx context.Context, unit string) (string, error) {
	return m.job(ctx, unit, (*sddbus.Conn).StopUnitContext)
}

func (m dbusManager) Restart(ctx context.Context, unit string) (string, error) {
	return m.job(ctx, unit, (*sddbus.Conn).RestartUnitContext)
}

// mapDBusError turns D-Bus errors into structured errors.
func mapDBusError(err error, unit string) error {
	var name string
	var de dbus.Error
	var dep *dbus.Error
	switch {
	case errors.As(err, &de):
		name = de.Name
	case errors.As(err, &dep):
		name = dep.Name
	}
	switch {
	case name == "org.freedesktop.systemd1.NoSuchUnit":
		return core.Errorf(core.CodeResourceNotFound, "unit %s not found", unit)
	case name == "org.freedesktop.DBus.Error.AccessDenied" ||
		name == "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired":
		return core.Errorf(core.CodePermissionDenied,
			"the operating system denied this operation on %s (check the sysrail polkit rule)", unit)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return err
	}
	return core.Errorf(core.CodeExecutionFailed, "systemd: %v", err)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func u64(v any) uint64 {
	n, _ := v.(uint64)
	return n
}

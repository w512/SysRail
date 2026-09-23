package systemd

import "context"

// Manager is the subset of the systemd manager API the provider needs. The
// production implementation talks to systemd over D-Bus; tests use a fake.
type Manager interface {
	// ListUnits returns loaded units matching states (empty: all) and glob
	// patterns.
	ListUnits(ctx context.Context, states, patterns []string) ([]UnitStatus, error)
	// Properties returns unit and service properties. Unknown units report
	// LoadState "not-found".
	Properties(ctx context.Context, unit string) (*UnitProperties, error)
	// Start, Stop and Restart enqueue a job in "replace" mode and wait for
	// it to finish, returning systemd's job result ("done", "failed", ...).
	Start(ctx context.Context, unit string) (string, error)
	Stop(ctx context.Context, unit string) (string, error)
	Restart(ctx context.Context, unit string) (string, error)
}

// UnitStatus is one entry of ListUnits.
type UnitStatus struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
}

// UnitProperties are the properties reported by service_get_status.
// Timestamps are microseconds since the epoch (0 = never).
type UnitProperties struct {
	Name                   string
	Description            string
	LoadState              string
	ActiveState            string
	SubState               string
	UnitFileState          string
	FragmentPath           string
	StateChangeTimestamp   uint64
	ActiveEnterTimestamp   uint64
	InactiveEnterTimestamp uint64
	// Service properties.
	MainPID        uint32
	NRestarts      uint32
	ExecMainStatus int32
	Result         string
	MemoryCurrent  uint64
}

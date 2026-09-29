// Package providers defines the interface implemented by platform providers
// (Linux, systemd, ...). Providers hold privileged access internally and only
// expose explicitly defined capabilities.
package providers

import (
	"context"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/events"
)

// Provider contributes capabilities to the registry.
type Provider interface {
	Name() string
	Capabilities() []core.Capability
}

// EventSource is implemented by providers that emit host events (spec §20).
// Watch runs until ctx is canceled.
type EventSource interface {
	Watch(ctx context.Context, publish func(events.Event))
}

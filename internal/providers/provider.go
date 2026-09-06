// Package providers defines the interface implemented by platform providers
// (Linux, systemd, ...). Providers hold privileged access internally and only
// expose explicitly defined capabilities.
package providers

import "github.com/w512/SysRail/internal/core"

// Provider contributes capabilities to the registry.
type Provider interface {
	Name() string
	Capabilities() []core.Capability
}

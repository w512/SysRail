package main

import (
	"log/slog"
	"runtime"

	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/providers"
	"github.com/w512/SysRail/internal/providers/linux"
	"github.com/w512/SysRail/internal/providers/systemd"
)

// buildProviders constructs the providers enabled in cfg. Providers must not
// touch the host during construction so that `policy check` stays harmless.
func buildProviders(cfg *config.Config, log *slog.Logger) ([]providers.Provider, error) {
	var out []providers.Provider
	onLinux := runtime.GOOS == "linux"
	if cfg.Providers.Linux.Enabled {
		if onLinux {
			out = append(out, linux.New(linux.Options{}))
		} else {
			log.Warn("linux provider disabled: not running on Linux")
		}
	}
	if cfg.Providers.Systemd.Enabled {
		if onLinux {
			out = append(out, systemd.New(systemd.Options{ProtectedUnits: cfg.Providers.Systemd.ProtectedUnits}))
		} else {
			log.Warn("systemd provider disabled: not running on Linux")
		}
	}
	return out, nil
}

package main

import (
	"log/slog"
	"runtime"

	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/providers"
	"github.com/w512/SysRail/internal/providers/linux"
)

// buildProviders constructs the providers enabled in cfg. Providers must not
// touch the host during construction so that `policy check` stays harmless.
func buildProviders(cfg *config.Config, log *slog.Logger) ([]providers.Provider, error) {
	var out []providers.Provider
	if cfg.Providers.Linux.Enabled {
		if runtime.GOOS == "linux" {
			out = append(out, linux.New(linux.Options{}))
		} else {
			log.Warn("linux provider disabled: not running on Linux")
		}
	}
	return out, nil
}

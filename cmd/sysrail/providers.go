package main

import (
	"log/slog"

	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/providers"
)

// buildProviders constructs the providers enabled in cfg. Providers must not
// touch the host during construction so that `policy check` stays harmless.
func buildProviders(cfg *config.Config, log *slog.Logger) ([]providers.Provider, error) {
	var out []providers.Provider
	return out, nil
}

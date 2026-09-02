// Package version holds build metadata injected via -ldflags.
package version

// Version is overridden at build time with
// -ldflags "-X github.com/w512/SysRail/internal/version.Version=...".
var Version = "dev"

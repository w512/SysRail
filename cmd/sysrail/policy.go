package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"text/tabwriter"

	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/server"
)

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(stderr, "Usage: sysrail policy check [--config FILE]")
		return 2
	}
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "path to config file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	provs, err := buildProviders(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	reg, err := server.BuildRegistry(cfg, provs, nil)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	pol, err := server.LoadPolicy(cfg, reg)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	fmt.Fprintf(stdout, "policy %s is valid\n", cfg.PolicyFile)
	for _, agent := range pol.Agents() {
		fmt.Fprintf(stdout, "\nagent %s:\n", agent)
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  TOOL\tPERMISSION\tDEFAULT\tRULE")
		for _, c := range reg.All() {
			if c.AlwaysAllowed || !pol.Reachable(agent, c.Permission) {
				continue
			}
			d := pol.Decide(agent, c.Permission, c.ResourceKind, "")
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", c.Tool, c.Permission, d.Action, d.Rule)
		}
		tw.Flush()
	}
	for name := range cfg.Agents {
		if !slices.Contains(pol.Agents(), name) {
			fmt.Fprintf(stdout, "\nwarning: agent %s has no policy and will be denied everything\n", name)
		}
	}
	return 0
}

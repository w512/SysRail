package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/notify"
	"github.com/w512/SysRail/internal/server"
)

func runNotify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(stderr, "Usage: sysrail notify test [--config FILE]")
		return 2
	}
	fs := flag.NewFlagSet("notify test", flag.ContinueOnError)
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
	host := server.Hostname()
	n := notify.New(notify.Options{Channels: server.NotificationChannels(cfg, host), Host: host})
	if len(n.Channels()) == 0 {
		fmt.Fprintln(stdout, "no notification channels are configured (see notifications in the config)")
		return 1
	}
	failed := false
	for _, r := range n.Test(context.Background()) {
		if r.Err != nil {
			failed = true
			fmt.Fprintf(stdout, "FAIL  %s: %v\n", r.Channel, r.Err)
			continue
		}
		fmt.Fprintf(stdout, "ok    %s\n", r.Channel)
	}
	if failed {
		return 1
	}
	return 0
}

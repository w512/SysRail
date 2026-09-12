package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/server"
	"github.com/w512/SysRail/internal/version"
)

func runServe(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	log := newLogger(cfg.Log.Level, stderr)
	d, err := server.New(cfg, buildProviders, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	defer d.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			if err := d.ReloadPolicy(); err != nil {
				log.Error("policy reload failed; keeping current policy", "error", err)
			} else {
				log.Info("policy reloaded", "file", cfg.PolicyFile)
			}
		}
	}()

	log.Info("sysrail starting", "version", version.Version, "capabilities", len(d.Engine().Registry().All()))
	if err := d.Run(ctx); err != nil {
		log.Error("server stopped", "error", err)
		return 1
	}
	log.Info("sysrail stopped")
	return 0
}

func newLogger(level string, w io.Writer) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

// Package server wires configuration, providers, policy, storage and the
// HTTP listeners into the running daemon.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/w512/SysRail/internal/api/httpapi"
	"github.com/w512/SysRail/internal/auth"
	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/engine"
	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/core/policy"
	"github.com/w512/SysRail/internal/core/request"
	"github.com/w512/SysRail/internal/notify"
	"github.com/w512/SysRail/internal/providers"
	"github.com/w512/SysRail/internal/retention"
	"github.com/w512/SysRail/internal/store/sqlite"
)

// ProviderFactory builds the providers enabled by cfg.
type ProviderFactory func(cfg *config.Config, log *slog.Logger) ([]providers.Provider, error)

// BuildRegistry builds the capability registry for cfg. store backs built-in
// capabilities and may be nil when the registry is only inspected.
func BuildRegistry(cfg *config.Config, provs []providers.Provider, store request.Store) (*core.Registry, error) {
	caps := engine.Builtins(store)
	for _, p := range provs {
		caps = append(caps, p.Capabilities()...)
	}
	return core.NewRegistry(core.RegistryOptions{
		ReadTimeout: cfg.Timeouts.Read, MutatingTimeout: cfg.Timeouts.Mutating,
	}, caps...)
}

// LoadPolicy reads and compiles the policy file against cfg and reg.
func LoadPolicy(cfg *config.Config, reg *core.Registry) (*policy.Policy, error) {
	data, err := os.ReadFile(cfg.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	f, err := policy.Parse(data)
	if err != nil {
		return nil, err
	}
	return policy.Compile(f, policy.Known{Agents: cfg.AgentNames(), Permissions: reg.Permissions()})
}

// Daemon is a configured, not yet running server.
type Daemon struct {
	cfg    *config.Config
	log    *slog.Logger
	store  *sqlite.Store
	engine *engine.Engine
	authn  *auth.Authenticator
	provs  []providers.Provider
	bus    *events.Bus
	notify *notify.Notifier
}

// New builds a daemon from cfg.
func New(cfg *config.Config, factory ProviderFactory, log *slog.Logger) (*Daemon, error) {
	if log == nil {
		log = slog.Default()
	}
	var provs []providers.Provider
	if factory != nil {
		var err error
		if provs, err = factory(cfg, log); err != nil {
			return nil, fmt.Errorf("providers: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Database), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	store, err := sqlite.Open(cfg.Database)
	if err != nil {
		return nil, err
	}
	d := &Daemon{cfg: cfg, log: log, store: store, provs: provs, bus: events.NewBus(1024)}
	if err := d.init(); err != nil {
		store.Close()
		return nil, err
	}
	return d, nil
}

func (d *Daemon) init() error {
	reg, err := BuildRegistry(d.cfg, d.provs, d.store)
	if err != nil {
		return fmt.Errorf("capabilities: %w", err)
	}
	pol, err := LoadPolicy(d.cfg, reg)
	if err != nil {
		return err
	}
	if d.authn, err = auth.NewAuthenticator(d.cfg.AgentHashes()); err != nil {
		return err
	}
	d.engine, err = engine.New(engine.Options{
		Registry: reg, Policy: pol, Store: d.store, ApprovalTTL: d.cfg.Approvals.TTL, Logger: d.log,
		Events: d.bus,
		Limits: func(agent string) engine.Limits {
			l := d.cfg.LimitsFor(agent)
			return engine.Limits{CallsPerMinute: l.CallsPerMinute, Burst: l.Burst, MaxPending: l.MaxPending}
		},
	})
	if err != nil {
		return err
	}
	host := Hostname()
	d.notify = notify.New(notify.Options{
		Channels: NotificationChannels(d.cfg, host), Host: host, Lookup: d.store.GetRequest, Log: d.log,
		Impact: func(id string) string {
			if c, ok := reg.ByID(id); ok {
				return c.Impact
			}
			return ""
		},
	})
	return nil
}

// Engine returns the daemon's engine.
func (d *Daemon) Engine() *engine.Engine { return d.engine }

// ReloadPolicy re-reads the policy file. On error the current policy stays.
func (d *Daemon) ReloadPolicy() error {
	pol, err := LoadPolicy(d.cfg, d.engine.Registry())
	if err != nil {
		return err
	}
	d.engine.SetPolicy(pol)
	return nil
}

// Close releases resources.
func (d *Daemon) Close() error { return d.store.Close() }

// Run serves until ctx is canceled.
func (d *Daemon) Run(ctx context.Context) error {
	agentHandler := httpapi.NewAgentHandler(d.engine, d.authn, d.log)
	type listener struct {
		name string
		ln   net.Listener
		srv  *http.Server
	}
	var lns []listener
	closeAll := func() {
		for _, l := range lns {
			l.ln.Close()
		}
	}
	// Canceled on shutdown so long-lived requests (event streams) end.
	// Mutations are detached from request cancellation by the engine.
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	newServer := func(h http.Handler, connCtx func(context.Context, net.Conn) context.Context) *http.Server {
		return &http.Server{
			Handler:           h,
			BaseContext:       func(net.Listener) context.Context { return baseCtx },
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      11 * time.Minute,
			IdleTimeout:       2 * time.Minute,
			ConnContext:       connCtx,
		}
	}

	admin, err := listenUnix(d.cfg.Server.AdminSocket, 0o600, "")
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	lns = append(lns, listener{"admin socket " + d.cfg.Server.AdminSocket, admin,
		newServer(httpapi.NewAdminHandler(d.engine, actorFromPeer, d.log), withPeerCred)})

	if s := d.cfg.Server.AgentSocket; s != "" {
		mode := os.FileMode(0o600)
		if d.cfg.Server.AgentSocketGroup != "" {
			mode = 0o660
		}
		ln, err := listenUnix(s, mode, d.cfg.Server.AgentSocketGroup)
		if err != nil {
			closeAll()
			return fmt.Errorf("agent socket: %w", err)
		}
		lns = append(lns, listener{"agent socket " + s, ln, newServer(agentHandler, nil)})
	}
	if addr := d.cfg.Server.HTTPListen; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			closeAll()
			return fmt.Errorf("http listener: %w", err)
		}
		h := agentHandler
		if d.cfg.Admin.TokenSHA256 != "" {
			h = httpapi.WithAdminToken(agentHandler,
				httpapi.NewAdminHandler(d.engine, func(r *http.Request) string { return "admin-token" }, d.log),
				d.cfg.Admin.TokenSHA256)
		}
		lns = append(lns, listener{"http " + ln.Addr().String(), ln, newServer(h, nil)})
	}

	errc := make(chan error, len(lns))
	var wg sync.WaitGroup
	watchCtx, stopWatchers := context.WithCancel(ctx)
	defer stopWatchers()
	if chans := d.notify.Channels(); len(chans) > 0 {
		for _, c := range chans {
			d.log.Info("notifications enabled", "channel", c.Name())
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.notify.Run(watchCtx, d.bus)
		}()
	}
	if days := d.cfg.Audit.RetentionDays; days > 0 {
		d.log.Info("audit retention enabled", "days", days, "archive", d.cfg.ArchiveDirectory())
		wg.Add(1)
		go func() {
			defer wg.Done()
			retention.Loop(watchCtx, retention.Options{
				Store: d.store, Days: days, ArchiveDir: d.cfg.ArchiveDirectory(), Log: d.log,
			}, time.Hour)
		}()
	}
	for _, p := range d.provs {
		if src, ok := p.(providers.EventSource); ok {
			d.log.Info("watching for events", "provider", p.Name())
			wg.Add(1)
			go func() {
				defer wg.Done()
				src.Watch(watchCtx, func(e events.Event) {
					e = d.bus.Publish(e)
					d.log.Info("event", "type", e.Type, "resource", e.Resource)
				})
			}()
		}
	}
	for _, l := range lns {
		d.log.Info("listening", "on", l.name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.srv.Serve(l.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", l.name, err)
			}
		}()
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-errc:
			runErr = err
			break loop
		case <-ticker.C:
			d.engine.FlushRateLimits(context.Background(), false)
			if n, err := d.engine.ExpireStale(context.Background()); err != nil {
				d.log.Error("expire stale requests", "error", err)
			} else if n > 0 {
				d.log.Info("expired stale requests", "count", n)
			}
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stopWatchers()
	cancelBase()
	d.engine.FlushRateLimits(context.Background(), true)
	for _, l := range lns {
		l.srv.Shutdown(shutdownCtx)
	}
	wg.Wait()
	for _, p := range []string{d.cfg.Server.AdminSocket, d.cfg.Server.AgentSocket} {
		if p != "" {
			os.Remove(p)
		}
	}
	return runErr
}

// listenUnix creates a Unix socket with the given mode, replacing a stale
// socket file but never any other kind of file.
func listenUnix(path string, mode os.FileMode, group string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(true)
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("look up group %q: %w", group, err)
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			return nil, fmt.Errorf("chown socket: %w", err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

type peerKey struct{}

func withPeerCred(ctx context.Context, c net.Conn) context.Context {
	if uc, ok := c.(*net.UnixConn); ok {
		if uid, ok := peerUID(uc); ok {
			return context.WithValue(ctx, peerKey{}, uid)
		}
	}
	return ctx
}

func actorFromPeer(r *http.Request) string {
	actor := "admin-socket"
	if uid, ok := r.Context().Value(peerKey{}).(uint32); ok {
		actor = fmt.Sprintf("uid=%d", uid)
		if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
			actor += "(" + u.Username + ")"
		}
	}
	if claimed := r.Header.Get(httpapi.ActorHeader); claimed != "" && len(claimed) <= 64 {
		actor += " via " + claimed
	}
	return actor
}

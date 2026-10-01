package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/auth"
	"github.com/w512/SysRail/internal/client"
	"github.com/w512/SysRail/internal/config"
	"github.com/w512/SysRail/internal/providers"
	"github.com/w512/SysRail/internal/providers/fake"
)

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestDaemonServesAgentAndAdminSockets(t *testing.T) {
	dir := shortDir(t)
	token, hash, _ := auth.NewToken()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nagents:\n  agent:\n    allow: [fake.read]\n    ask: [fake.restart]\n"), 0o600)
	cfg := config.Default()
	cfg.Server.HTTPListen = ""
	cfg.Server.AgentSocket = filepath.Join(dir, "agent.sock")
	cfg.Server.AdminSocket = filepath.Join(dir, "admin.sock")
	cfg.Database = filepath.Join(dir, "state", "sysrail.db")
	cfg.PolicyFile = policyPath
	cfg.Agents = map[string]config.Agent{"agent": {TokenSHA256: hash}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	fp := fake.New()
	log := slog.New(slog.DiscardHandler)
	d, err := New(cfg, func(*config.Config, *slog.Logger) ([]providers.Provider, error) {
		return []providers.Provider{fp}, nil
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	agent, _ := client.New(cfg.Server.AgentSocket, token)
	admin, _ := client.New("unix://"+cfg.Server.AdminSocket, "")
	if err := agent.Wait(ctx, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{cfg.Server.AdminSocket: 0o600, cfg.Server.AgentSocket: 0o600} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want || fi.Mode()&os.ModeSocket == 0 {
			t.Fatalf("%s: %v %v", path, fi.Mode(), err)
		}
	}

	var out struct {
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
	}
	status, err := agent.Do(ctx, http.MethodPost, "/v1/execute",
		map[string]any{"capability": "fake.restart", "arguments": map[string]string{"name": "w"}}, &out)
	if err != nil || status != http.StatusAccepted || out.RequestID == "" {
		t.Fatalf("execute: %d %v %+v", status, err, out)
	}
	if _, err := agent.Do(ctx, http.MethodGet, "/v1/requests", nil, nil); err == nil {
		t.Fatal("agent socket served the admin API")
	}
	admin.SetHeader("X-SysRail-Actor", "tester")
	var req struct {
		Status    string `json:"status"`
		DecidedBy string `json:"decided_by"`
	}
	if _, err := admin.Do(ctx, http.MethodPost, "/v1/requests/"+out.RequestID+"/approve", map[string]any{}, &req); err != nil {
		t.Fatal(err)
	}
	if req.Status != "executed" || fp.Restarts("w") != 1 {
		t.Fatalf("approve: %+v restarts=%d", req, fp.Restarts("w"))
	}
	t.Logf("decided_by=%q", req.DecidedBy)

	os.WriteFile(policyPath, []byte("version: 1\nagents:\n  agent:\n    deny: [fake.read]\n"), 0o600)
	if err := d.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Do(ctx, http.MethodPost, "/v1/execute", map[string]any{"capability": "fake.status"}, nil); err == nil {
		t.Fatal("reloaded policy not applied")
	}
	os.WriteFile(policyPath, []byte("version: 1\nagents:\n  ghost: {}\n"), 0o600)
	if err := d.ReloadPolicy(); err == nil {
		t.Fatal("invalid policy accepted on reload")
	}

	// An open event stream must not hold up shutdown.
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		admin.Do(context.Background(), http.MethodGet, "/v1/events", nil, nil)
	}()
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("shutdown with an open event stream took %s", took)
	}
	<-streamDone
	for _, p := range []string{cfg.Server.AdminSocket, cfg.Server.AgentSocket} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s not removed on shutdown", p)
		}
	}
}

func TestDaemonRefusesToStartWithBadPolicy(t *testing.T) {
	dir := shortDir(t)
	_, hash, _ := auth.NewToken()
	cfg := config.Default()
	cfg.Database = filepath.Join(dir, "sysrail.db")
	cfg.PolicyFile = filepath.Join(dir, "policy.yaml")
	cfg.Agents = map[string]config.Agent{"agent": {TokenSHA256: hash}}
	for name, body := range map[string]string{
		"typo":          "version: 1\nagents:\n  agent:\n    allow: [fake.raed]\n",
		"unknown agent": "version: 1\nagents:\n  stranger:\n    allow: [fake.read]\n",
		"unknown field": "version: 1\nagent:\n  agent: {}\n",
	} {
		os.WriteFile(cfg.PolicyFile, []byte(body), 0o600)
		if d, err := New(cfg, func(*config.Config, *slog.Logger) ([]providers.Provider, error) {
			return []providers.Provider{fake.New()}, nil
		}, slog.New(slog.DiscardHandler)); err == nil {
			d.Close()
			t.Errorf("%s: daemon started with an invalid policy", name)
		}
	}
}

func TestListenUnixRefusesToReplaceRegularFile(t *testing.T) {
	path := filepath.Join(shortDir(t), "x.sock")
	os.WriteFile(path, []byte("data"), 0o600)
	if _, err := listenUnix(path, 0o600, ""); err == nil {
		t.Fatal("regular file replaced by socket")
	}
}

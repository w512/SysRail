package systemd

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/providers/providertest"
)

type fakeManager struct {
	mu        sync.Mutex
	units     map[string]*UnitProperties
	jobs      []string
	jobResult string
}

func newFakeManager() *fakeManager {
	return &fakeManager{jobResult: "done", units: map[string]*UnitProperties{
		"nginx.service": {Name: "nginx.service", Description: "A high performance web server", LoadState: "loaded",
			ActiveState: "failed", SubState: "failed", UnitFileState: "enabled", NRestarts: 3, ExecMainStatus: 1,
			Result: "exit-code", MemoryCurrent: ^uint64(0), StateChangeTimestamp: 1790958522758072,
			FragmentPath: "/usr/lib/systemd/system/nginx.service"},
		"cron.service": {Name: "cron.service", Description: "Regular background program processing daemon",
			LoadState: "loaded", ActiveState: "active", SubState: "running", MainPID: 812, MemoryCurrent: 1 << 20,
			ActiveEnterTimestamp: 1790958522758072},
		"ssh.service":     {Name: "ssh.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
		"sysrail.service": {Name: "sysrail.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
		"dbus.socket":     {Name: "dbus.socket", LoadState: "loaded", ActiveState: "active", SubState: "listening"},
	}}
}

func (f *fakeManager) ListUnits(_ context.Context, states, patterns []string) ([]UnitStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []UnitStatus
	for name, u := range f.units {
		if len(patterns) > 0 {
			if ok, _ := path.Match(patterns[0], name); !ok {
				continue
			}
		}
		if len(states) > 0 && !slices.Contains(states, u.ActiveState) && !slices.Contains(states, u.SubState) {
			continue
		}
		out = append(out, UnitStatus{Name: name, Description: u.Description, LoadState: u.LoadState,
			ActiveState: u.ActiveState, SubState: u.SubState})
	}
	return out, nil
}

func (f *fakeManager) Properties(_ context.Context, unit string) (*UnitProperties, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.units[unit]
	if !ok {
		return &UnitProperties{Name: unit, LoadState: "not-found", ActiveState: "inactive", SubState: "dead"}, nil
	}
	cp := *u
	return &cp, nil
}

func (f *fakeManager) job(verb, unit, active, sub string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, verb+" "+unit)
	if f.jobResult == "done" {
		f.units[unit].ActiveState, f.units[unit].SubState = active, sub
	}
	return f.jobResult, nil
}

func (f *fakeManager) Start(_ context.Context, u string) (string, error) {
	return f.job("start", u, "active", "running")
}
func (f *fakeManager) Stop(_ context.Context, u string) (string, error) {
	return f.job("stop", u, "inactive", "dead")
}
func (f *fakeManager) Restart(_ context.Context, u string) (string, error) {
	return f.job("restart", u, "active", "running")
}

const journalFixture = `{"__REALTIME_TIMESTAMP":"1790958522758072","PRIORITY":"6","SYSLOG_IDENTIFIER":"nginx","_PID":"4242","MESSAGE":"starting nginx"}
{"__REALTIME_TIMESTAMP":"1790958523000000","PRIORITY":"3","SYSLOG_IDENTIFIER":"nginx","_PID":"4242","MESSAGE":"bind() to 0.0.0.0:80 failed (98: Address already in use)"}
{"__REALTIME_TIMESTAMP":"1790958524000000","PRIORITY":"3","SYSLOG_IDENTIFIER":"nginx","_PID":"4242","MESSAGE":[98,105,110,97,114,121,255]}
not json
{"__REALTIME_TIMESTAMP":"1790958525000000","PRIORITY":"4","SYSLOG_IDENTIFIER":"systemd","_PID":"1","MESSAGE":"nginx.service: Failed with result 'exit-code'."}
`

type harness struct {
	p           *Provider
	m           *fakeManager
	journalArgs []string
	journalOut  string
}

func newHarness(opts Options) *harness {
	h := &harness{m: newFakeManager(), journalOut: journalFixture}
	opts.Manager = h.m
	opts.Journal = func(_ context.Context, args []string) ([]byte, error) {
		h.journalArgs = args
		return []byte(h.journalOut), nil
	}
	h.p = New(opts)
	return h
}

func (h *harness) run(t *testing.T, tool, args string) (map[string]any, *core.Error) {
	t.Helper()
	for _, c := range h.p.Capabilities() {
		if c.Tool != tool {
			continue
		}
		inv, err := c.Bind(json.RawMessage(args))
		if err != nil {
			return nil, core.AsError(err)
		}
		out, err := inv.Run(context.Background())
		if err != nil {
			return nil, core.AsError(err)
		}
		b, _ := json.Marshal(out)
		var m map[string]any
		json.Unmarshal(b, &m)
		return m, nil
	}
	t.Fatalf("no tool %s", tool)
	return nil, nil
}

func TestNormalizeUnit(t *testing.T) {
	ok := map[string]string{
		"nginx": "nginx.service", " nginx.service ": "nginx.service", "getty@tty1": "getty@tty1.service",
		"foo@bar.service": "foo@bar.service", `systemd-fsck@dev-disk\x2dby\x2duuid.service`: `systemd-fsck@dev-disk\x2dby\x2duuid.service`,
		"user_app:1": "user_app:1.service",
	}
	for in, want := range ok {
		if got, err := NormalizeUnit(in); err != nil || got != want {
			t.Errorf("NormalizeUnit(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "-rf", "--help", "nginx; rm -rf /", "../etc/passwd", "/etc/passwd", "a b", "$(reboot)",
		"multi-user.target", "dbus.socket", "home.mount", "foo@.service", `x\y`, "nginx\x00", strings.Repeat("a", 250),
	} {
		if got, err := NormalizeUnit(bad); err == nil {
			t.Errorf("NormalizeUnit(%q) = %q, want error", bad, got)
		}
	}
}

func TestProtectedUnits(t *testing.T) {
	h := newHarness(Options{})
	for _, unit := range []string{"sysrail", "ssh.service", "systemd-journald", "dbus", "user@1000"} {
		for _, tool := range []string{"service_stop", "service_restart", "service_start"} {
			if _, err := h.run(t, tool, `{"name":"`+unit+`"}`); err == nil || err.Code != core.CodePermissionDenied {
				t.Errorf("%s %s: got %v, want PERMISSION_DENIED", tool, unit, err)
			}
		}
	}
	if len(h.m.jobs) != 0 {
		t.Fatalf("protected unit reached systemd: %v", h.m.jobs)
	}
	if _, err := h.run(t, "service_get_status", `{"name":"ssh"}`); err != nil {
		t.Fatalf("reads of protected units must work: %v", err)
	}

	custom := newHarness(Options{ProtectedUnits: []string{}})
	if _, err := custom.run(t, "service_restart", `{"name":"ssh"}`); err != nil {
		t.Fatalf("ssh should be manageable with an empty protected list: %v", err)
	}
	if _, err := custom.run(t, "service_stop", `{"name":"sysrail.service"}`); err == nil || err.Code != core.CodePermissionDenied {
		t.Fatalf("sysrail.service must always be protected, got %v", err)
	}
}

func TestList(t *testing.T) {
	h := newHarness(Options{})
	m, err := h.run(t, "service_list", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	svcs := m["services"].([]any)
	if len(svcs) != 4 || svcs[0].(map[string]any)["name"] != "cron.service" {
		t.Fatalf("all services (sorted, no sockets): %v", svcs)
	}
	m, _ = h.run(t, "service_list", `{"state":"failed"}`)
	if svcs := m["services"].([]any); len(svcs) != 1 || svcs[0].(map[string]any)["name"] != "nginx.service" {
		t.Fatalf("failed services: %v", svcs)
	}
	m, _ = h.run(t, "service_list", `{"pattern":"ngin*"}`)
	if len(m["services"].([]any)) != 1 {
		t.Fatalf("pattern: %v", m)
	}
	m, _ = h.run(t, "service_list", `{"limit":2}`)
	if len(m["services"].([]any)) != 2 || m["truncated"] != true || m["total"] != 4.0 {
		t.Fatalf("limit: %v", m)
	}
	for _, bad := range []string{`{"pattern":"a b"}`, `{"pattern":"$(x)"}`, `{"state":"weird"}`, `{"limit":5000}`} {
		if _, err := h.run(t, "service_list", bad); err == nil || err.Code != core.CodeInvalidArgument {
			t.Errorf("%s: got %v", bad, err)
		}
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(Options{})
	m, err := h.run(t, "service_get_status", `{"name":"nginx"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m["name"] != "nginx.service" || m["healthy"] != false || m["restarts"] != 3.0 || m["exec_main_status"] != 1.0 ||
		m["result"] != "exit-code" || m["state_changed_at"] != "2026-10-02T16:28:42.758072Z" {
		t.Fatalf("nginx: %v", m)
	}
	if _, ok := m["memory_bytes"]; ok {
		t.Fatal("unknown memory (UINT64_MAX) must be omitted")
	}
	m, _ = h.run(t, "service_get_status", `{"name":"cron"}`)
	if m["healthy"] != true || m["main_pid"] != 812.0 || m["memory_bytes"] != float64(1<<20) {
		t.Fatalf("cron: %v", m)
	}
	if _, err := h.run(t, "service_get_status", `{"name":"nope"}`); err == nil || err.Code != core.CodeResourceNotFound {
		t.Fatalf("missing unit: %v", err)
	}
}

func TestLogs(t *testing.T) {
	h := newHarness(Options{})
	m, err := h.run(t, "service_get_logs", `{"name":"nginx","lines":50,"since_minutes":30,"priority":"warning"}`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--unit=nginx.service", "--output=json", "--lines=50", "--no-pager", "--quiet", "--since=-30min", "--priority=warning"}
	if !slices.Equal(h.journalArgs, want) {
		t.Fatalf("journalctl args %v, want %v", h.journalArgs, want)
	}
	entries := m["entries"].([]any)
	if len(entries) != 4 || m["count"] != 4.0 || m["truncated"] != false {
		t.Fatalf("entries: %v", m)
	}
	e1 := entries[1].(map[string]any)
	if e1["priority"] != "err" || e1["pid"] != 4242.0 || e1["identifier"] != "nginx" ||
		!strings.Contains(e1["message"].(string), "Address already in use") || e1["time"] != "2026-10-02T16:28:43Z" {
		t.Fatalf("entry: %v", e1)
	}
	if msg := entries[2].(map[string]any)["message"]; msg != "binary\uFFFD" {
		t.Fatalf("byte-array message: %q", msg)
	}

	if _, err := h.run(t, "service_get_logs", `{"name":"nginx"}`); err != nil || h.journalArgs[2] != "--lines=100" {
		t.Fatalf("default lines: %v %v", h.journalArgs, err)
	}
	for _, bad := range []string{`{"name":"nginx","lines":5000}`, `{"name":"nginx","priority":"loud"}`, `{"name":"--all"}`} {
		if _, err := h.run(t, "service_get_logs", bad); err == nil || err.Code != core.CodeInvalidArgument {
			t.Errorf("%s: got %v", bad, err)
		}
	}

	h.journalOut = ""
	if m, err := h.run(t, "service_get_logs", `{"name":"cron"}`); err != nil || m["count"] != 0.0 {
		t.Fatalf("quiet unit: %v %v", m, err)
	}
	if _, err := h.run(t, "service_get_logs", `{"name":"nope"}`); err == nil || err.Code != core.CodeResourceNotFound {
		t.Fatalf("unknown unit: %v", err)
	}
}

func TestLogsAreCappedKeepingNewest(t *testing.T) {
	h := newHarness(Options{MaxLogBytes: 50})
	m, err := h.run(t, "service_get_logs", `{"name":"nginx"}`)
	if err != nil {
		t.Fatal(err)
	}
	entries := m["entries"].([]any)
	if m["truncated"] != true || len(entries) != 1 ||
		!strings.HasPrefix(entries[0].(map[string]any)["message"].(string), "nginx.service: Failed") {
		t.Fatalf("cap: %v", m)
	}
}

func TestMutations(t *testing.T) {
	h := newHarness(Options{})
	m, err := h.run(t, "service_restart", `{"name":"nginx"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m["unit"] != "nginx.service" || m["action"] != "restart" || m["job_result"] != "done" || m["active_state"] != "active" {
		t.Fatalf("restart: %v", m)
	}
	if _, err := h.run(t, "service_stop", `{"name":"cron"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run(t, "service_start", `{"name":"cron"}`); err != nil {
		t.Fatal(err)
	}
	if want := []string{"restart nginx.service", "stop cron.service", "start cron.service"}; !slices.Equal(h.m.jobs, want) {
		t.Fatalf("jobs %v, want %v", h.m.jobs, want)
	}
	if _, err := h.run(t, "service_restart", `{"name":"ghost"}`); err == nil || err.Code != core.CodeResourceNotFound {
		t.Fatalf("missing unit: %v", err)
	}
	if len(h.m.jobs) != 3 {
		t.Fatal("job enqueued for a missing unit")
	}
	for result, code := range map[string]core.Code{
		"failed": core.CodeExecutionFailed, "timeout": core.CodeTimeout,
		"canceled": core.CodeConflict, "dependency": core.CodeExecutionFailed,
	} {
		h.m.jobResult = result
		if _, err := h.run(t, "service_start", `{"name":"nginx"}`); err == nil || err.Code != code {
			t.Errorf("job result %s: got %v, want %s", result, err, code)
		}
	}
}

func TestCapabilityMetadata(t *testing.T) {
	r, err := core.NewRegistry(core.RegistryOptions{}, newHarness(Options{}).p.Capabilities()...)
	if err != nil {
		t.Fatal(err)
	}
	perms := r.Permissions()
	for _, p := range []string{"service.read", "logs.read", "service.start", "service.stop", "service.restart"} {
		if !perms[p]["service"] {
			t.Errorf("%s must be scoped to service resources: %v", p, perms[p])
		}
	}
	stop, _ := r.ByTool("service_stop")
	if stop.Risk != core.RiskMedium || stop.Impact == "" {
		t.Fatalf("stop: %+v", stop)
	}
}

func TestContract(t *testing.T) {
	providertest.Run(t, newHarness(Options{}).p, providertest.Options{Examples: map[string]string{
		"service.list":    `{}`,
		"service.status":  `{"name":"cron"}`,
		"service.logs":    `{"name":"nginx"}`,
		"service.restart": `{"name":"nginx"}`,
	}})
}

func TestJournalFailureIsUnavailable(t *testing.T) {
	p := New(Options{Manager: newFakeManager(), Journal: func(context.Context, []string) ([]byte, error) {
		return nil, errors.New("exit status 1")
	}})
	h := &harness{p: p}
	if _, err := h.run(t, "service_get_logs", `{"name":"nginx"}`); err == nil || err.Code != core.CodeProviderUnavailable {
		t.Fatalf("got %v", err)
	}
}

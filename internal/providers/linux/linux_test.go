package linux

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
)

func testProvider(t *testing.T, opts Options) *Provider {
	t.Helper()
	if opts.Root == nil {
		opts.Root = os.DirFS("testdata/root")
	}
	if opts.CPUSample == 0 {
		opts.CPUSample = time.Millisecond
	}
	if opts.LookPath == nil {
		opts.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	}
	return New(opts)
}

// call runs a capability by tool name and decodes its JSON result.
func call(t *testing.T, p *Provider, tool, args string) map[string]any {
	t.Helper()
	for _, c := range p.Capabilities() {
		if c.Tool != tool {
			continue
		}
		inv, err := c.Bind(json.RawMessage(args))
		if err != nil {
			t.Fatalf("%s: bind: %v", tool, err)
		}
		out, err := inv.Run(context.Background())
		if err != nil {
			t.Fatalf("%s: run: %v", tool, err)
		}
		b, _ := json.Marshal(out)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: result is not an object: %s", tool, b)
		}
		return m
	}
	t.Fatalf("no tool %s", tool)
	return nil
}

func TestCapabilitiesRegister(t *testing.T) {
	if _, err := core.NewRegistry(core.RegistryOptions{}, testProvider(t, Options{}).Capabilities()...); err != nil {
		t.Fatal(err)
	}
}

func TestSystemStatus(t *testing.T) {
	m := call(t, testProvider(t, Options{}), "system_get_status", `{}`)
	if m["hostname"] != "testhost" || m["kernel"] != "7.0.0-34-generic" || m["cpu_count"] != 2.0 ||
		m["uptime_seconds"] != 7344.0 {
		t.Fatalf("status: %v", m)
	}
	if os := m["os"].(map[string]any); os["pretty_name"] != "Ubuntu 24.04.5 LTS" || os["id"] != "ubuntu" {
		t.Fatalf("os: %v", os)
	}
	if la := m["load_average"].(map[string]any); la["1m"] != 0.5 || la["15m"] != 0.1 {
		t.Fatalf("load: %v", la)
	}
	if mem := m["memory"].(map[string]any); mem["used_percent"] != 25.0 || mem["total_bytes"] != 16000000.0*1024 {
		t.Fatalf("memory: %v", mem)
	}
	if pr := m["processes"].(map[string]any); pr["running"] != 2.0 || pr["total"] != 694.0 {
		t.Fatalf("processes: %v", pr)
	}
}

func TestCPUStatus(t *testing.T) {
	m := call(t, testProvider(t, Options{}), "system_get_cpu_status", `{"per_cpu":true}`)
	if m["model"] != "AMD Ryzen 7 7700 8-Core Processor" || m["logical_cpus"] != 2.0 {
		t.Fatalf("cpu: %v", m)
	}
	if f := m["frequency"].(map[string]any); f["max_mhz"] != 5086.5 || f["min_mhz"] != 3000.0 || f["avg_mhz"] != 4043.3 {
		t.Fatalf("frequency: %v", f)
	}
	if per := m["per_cpu_usage_percent"].([]any); len(per) != 2 {
		t.Fatalf("per cpu: %v", per)
	}
	if _, ok := call(t, testProvider(t, Options{}), "system_get_cpu_status", `{}`)["per_cpu_usage_percent"]; ok {
		t.Fatal("per-CPU usage returned without per_cpu")
	}
}

func TestUsagePercent(t *testing.T) {
	prev := cpuTimes{idle: 100, total: 200}
	if got := usagePercent(prev, cpuTimes{idle: 150, total: 400}); got != 75 {
		t.Fatalf("got %v", got)
	}
	if got := usagePercent(prev, prev); got != 0 {
		t.Fatalf("no time elapsed: %v", got)
	}
	all, per, err := parseStat([]byte("cpu  10 0 10 70 10 0 0 0 5 5\ncpu0 1 2 3 4 5 6 7 8 9 10\n"))
	if err != nil || all.total != 100 || all.idle != 80 || len(per) != 1 {
		t.Fatalf("parseStat: %+v %+v %v", all, per, err)
	}
}

func TestMemoryStatus(t *testing.T) {
	m := call(t, testProvider(t, Options{}), "system_get_memory_status", `{}`)
	if m["used_bytes"] != 4000000.0*1024 || m["used_percent"] != 25.0 || m["cached_bytes"] != 7000000.0*1024 {
		t.Fatalf("memory: %v", m)
	}
	if s := m["swap"].(map[string]any); s["used_bytes"] != 2000000.0*1024 || s["used_percent"] != 25.0 {
		t.Fatalf("swap: %v", s)
	}
}

func TestMissingProcIsProviderUnavailable(t *testing.T) {
	p := testProvider(t, Options{Root: os.DirFS(t.TempDir())})
	for _, c := range p.Capabilities() {
		if c.ID == "system.gpu" {
			continue // no GPU is a valid answer, not an error
		}
		inv, err := c.Bind(nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = inv.Run(context.Background())
		if e := core.AsError(err); e == nil || e.Code != core.CodeProviderUnavailable {
			t.Fatalf("%s: got %v", c.Tool, err)
		}
	}
}

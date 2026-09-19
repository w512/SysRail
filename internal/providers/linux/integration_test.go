//go:build linux && integration

package linux

import (
	"os/exec"
	"testing"

	"github.com/w512/SysRail/internal/providers/providertest"
)

// These tests read the real host. Run them on the Linux test machine with
// `make test-remote`.

func TestHostContract(t *testing.T) {
	providertest.Run(t, New(Options{}), providertest.Options{Examples: contractExamples})
}

func TestHostValues(t *testing.T) {
	p := New(Options{})
	st := call(t, p, "system_get_status", `{}`)
	if st["hostname"] == "" || st["kernel"] == "" || st["cpu_count"].(float64) < 1 {
		t.Fatalf("status: %v", st)
	}
	if mem := st["memory"].(map[string]any); mem["total_bytes"].(float64) <= 0 {
		t.Fatalf("memory: %v", mem)
	}
	cpu := call(t, p, "system_get_cpu_status", `{}`)
	if u := cpu["usage_percent"].(float64); u < 0 || u > 100 {
		t.Fatalf("cpu usage %v", u)
	}
	storage := call(t, p, "storage_get_status", `{}`)
	found := false
	for _, f := range storage["filesystems"].([]any) {
		fm := f.(map[string]any)
		if fm["mount_point"] == "/" {
			found = true
			if fm["total_bytes"].(float64) <= 0 || fm["error"] != nil {
				t.Fatalf("root filesystem: %v", fm)
			}
		}
	}
	if !found {
		t.Fatalf("root filesystem missing: %v", storage)
	}
	if conns := call(t, p, "network_get_connections", `{}`)["connections"].([]any); len(conns) == 0 {
		t.Fatal("no listening sockets found")
	}
	gpu := call(t, p, "system_get_gpu_status", `{}`)
	if _, err := exec.LookPath("nvidia-smi"); err == nil {
		gpus := gpu["gpus"].([]any)
		if gpu["available"] != true || len(gpus) == 0 || gpus[0].(map[string]any)["source"] != "nvidia-smi" {
			t.Fatalf("nvidia-smi present but GPU not reported: %v", gpu)
		}
		t.Logf("GPU: %v", gpus[0].(map[string]any)["name"])
	}
}

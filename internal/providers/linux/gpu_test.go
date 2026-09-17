package linux

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

const nvidiaOutput = "0, NVIDIA GeForce RTX 4060 Ti, GPU-e32d4ce6-600d-b6d7-572d-776ed0d2576d, 580.178.04, 16380, 397, 12, 39, 13.41\n"

func TestGPUStatusWithNvidiaSMI(t *testing.T) {
	var gotArgs []string
	p := testProvider(t, Options{
		LookPath: func(string) (string, error) { return "/usr/bin/nvidia-smi", nil },
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotArgs = append([]string{name}, args...)
			return []byte(nvidiaOutput), nil
		},
	})
	m := call(t, p, "system_get_gpu_status", `{}`)
	if gotArgs[0] != "/usr/bin/nvidia-smi" || !slices.Equal(gotArgs[1:], nvidiaQuery) {
		t.Fatalf("command: %v", gotArgs)
	}
	gpus := m["gpus"].([]any)
	if m["available"] != true || len(gpus) != 2 {
		t.Fatalf("want NVIDIA from nvidia-smi plus AMD from sysfs (NVIDIA sysfs card skipped): %v", gpus)
	}
	nv := gpus[0].(map[string]any)
	if nv["id"] != "nvidia:0" || nv["name"] != "NVIDIA GeForce RTX 4060 Ti" || nv["memory_total_bytes"] != float64(16380<<20) ||
		nv["utilization_percent"] != 12.0 || nv["temperature_c"] != 39.0 || nv["power_watts"] != 13.4 ||
		nv["memory_used_percent"] != 2.4 || nv["driver_version"] != "580.178.04" {
		t.Fatalf("nvidia: %v", nv)
	}
	amd := gpus[1].(map[string]any)
	if amd["id"] != "drm:card0" || amd["vendor"] != "AMD" || amd["driver"] != "amdgpu" || amd["pci_id"] != "1002:164e" ||
		amd["memory_used_percent"] != 10.0 || amd["utilization_percent"] != 7.0 || amd["source"] != "sysfs" {
		t.Fatalf("amd: %v", amd)
	}
}

func TestGPUStatusWithoutNvidiaSMI(t *testing.T) {
	p := testProvider(t, Options{LookPath: func(string) (string, error) { return "", errors.New("not found") }})
	gpus := call(t, p, "system_get_gpu_status", `{}`)["gpus"].([]any)
	if len(gpus) != 2 || gpus[1].(map[string]any)["vendor"] != "NVIDIA" {
		t.Fatalf("NVIDIA card must come from sysfs when nvidia-smi is missing: %v", gpus)
	}
}

func TestGPUStatusNoGPU(t *testing.T) {
	p := testProvider(t, Options{
		Root:     os.DirFS(t.TempDir()),
		LookPath: func(string) (string, error) { return "/usr/bin/nvidia-smi", nil },
		Command: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("exit status 9\nNVIDIA-SMI has failed")
		},
	})
	m := call(t, p, "system_get_gpu_status", `{}`)
	if m["available"] != false || len(m["gpus"].([]any)) != 0 {
		t.Fatalf("no GPU: %v", m)
	}
	if errs := m["errors"].([]any); len(errs) != 1 || errs[0] != "nvidia-smi failed: exit status 9" {
		t.Fatalf("errors: %v", errs)
	}
}

func TestParseNvidiaSMINotSupported(t *testing.T) {
	gpus, err := parseNvidiaSMI([]byte("0, Tesla T4, [N/A], 535.1, 15360, [N/A], [Not Supported], 40, [N/A]\n"))
	if err != nil || len(gpus) != 1 {
		t.Fatal(err)
	}
	g := gpus[0]
	if g.UUID != "" || g.MemoryUsedBytes != nil || g.UtilizationPercent != nil || g.PowerWatts != nil || *g.TemperatureC != 40 {
		t.Fatalf("%+v", g)
	}
}

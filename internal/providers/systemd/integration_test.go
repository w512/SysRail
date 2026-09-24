//go:build linux && integration

package systemd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/providers/providertest"
)

// These tests talk to the real systemd on the Linux test machine and only
// ever touch the sysrail-test-dummy unit they install. Run with
// `make test-remote` (as root).

const dummyUnit = "sysrail-test-dummy.service"

const dummyUnitFile = `[Unit]
Description=SysRail integration test dummy

[Service]
Type=simple
ExecStart=/bin/sh -c 'echo "sysrail dummy started"; exec sleep infinity'
`

func installDummy(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to install a test unit")
	}
	path := "/run/systemd/system/" + dummyUnit
	if err := os.WriteFile(path, []byte(dummyUnitFile), 0o644); err != nil {
		t.Fatal(err)
	}
	systemctl(t, "daemon-reload")
	t.Cleanup(func() {
		exec.Command("systemctl", "stop", dummyUnit).Run()
		os.Remove(path)
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "reset-failed", dummyUnit).Run()
	})
}

func systemctl(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
		t.Fatalf("systemctl %v: %v: %s", args, err, out)
	}
}

func TestHostServiceLifecycle(t *testing.T) {
	installDummy(t)
	h := &harness{p: New(Options{})}

	m, err := h.run(t, "service_get_status", `{"name":"sysrail-test-dummy"}`)
	if err != nil || m["active_state"] != "inactive" || m["load_state"] != "loaded" {
		t.Fatalf("initial status: %v %v", m, err)
	}
	m, err = h.run(t, "service_start", `{"name":"sysrail-test-dummy"}`)
	if err != nil || m["job_result"] != "done" || m["active_state"] != "active" || m["main_pid"] == nil {
		t.Fatalf("start: %v %v", m, err)
	}
	firstPID := m["main_pid"]

	var logs map[string]any
	for range 20 {
		if logs, err = h.run(t, "service_get_logs", `{"name":"sysrail-test-dummy","lines":20}`); err == nil && logs["count"].(float64) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || !strings.Contains(fmtEntries(logs), "sysrail dummy started") {
		t.Fatalf("logs: %v %v", logs, err)
	}

	m, err = h.run(t, "service_restart", `{"name":"sysrail-test-dummy"}`)
	if err != nil || m["active_state"] != "active" || m["main_pid"] == firstPID {
		t.Fatalf("restart: %v %v (first pid %v)", m, err, firstPID)
	}
	m, err = h.run(t, "service_list", `{"pattern":"sysrail-test-*","state":"running"}`)
	if err != nil || len(m["services"].([]any)) != 1 {
		t.Fatalf("list: %v %v", m, err)
	}
	m, err = h.run(t, "service_stop", `{"name":"sysrail-test-dummy"}`)
	if err != nil || m["active_state"] != "inactive" {
		t.Fatalf("stop: %v %v", m, err)
	}
}

func TestHostErrors(t *testing.T) {
	h := &harness{p: New(Options{})}
	if _, err := h.run(t, "service_get_status", `{"name":"sysrail-does-not-exist"}`); err == nil || err.Code != core.CodeResourceNotFound {
		t.Fatalf("missing unit: %v", err)
	}
	if _, err := h.run(t, "service_restart", `{"name":"sysrail-does-not-exist"}`); err == nil || err.Code != core.CodeResourceNotFound {
		t.Fatalf("restart missing unit: %v", err)
	}
	if _, err := h.run(t, "service_stop", `{"name":"ssh"}`); err == nil || err.Code != core.CodePermissionDenied {
		t.Fatalf("protected unit: %v", err)
	}
	if _, err := h.run(t, "service_get_logs", `{"name":"sysrail-does-not-exist"}`); err == nil || err.Code != core.CodeResourceNotFound {
		t.Fatalf("logs of missing unit: %v", err)
	}
}

func TestHostContract(t *testing.T) {
	installDummy(t)
	providertest.Run(t, New(Options{}), providertest.Options{Examples: map[string]string{
		"service.list":    `{"state":"failed"}`,
		"service.status":  `{"name":"dbus"}`,
		"service.logs":    `{"name":"dbus","lines":5}`,
		"service.start":   `{"name":"sysrail-test-dummy"}`,
		"service.restart": `{"name":"sysrail-test-dummy"}`,
		"service.stop":    `{"name":"sysrail-test-dummy"}`,
	}})
}

func fmtEntries(m map[string]any) string {
	var b strings.Builder
	for _, e := range m["entries"].([]any) {
		b.WriteString(e.(map[string]any)["message"].(string))
		b.WriteByte('\n')
	}
	return b.String()
}

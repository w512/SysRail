//go:build linux && e2e

// Package e2e drives a deployed SysRail daemon through the real `sysrail mcp`
// binary, the way an agent host does. It needs the test host prepared by
// scripts/deploy-remote.sh and runs as root (`make e2e-remote`).
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/w512/SysRail/internal/client"
)

const (
	binary   = "/usr/local/bin/sysrail"
	tokenDir = "/root/sysrail-e2e"
	dummy    = "sysrail-test-dummy.service"
)

func token(t *testing.T, agent string) string {
	t.Helper()
	b, err := os.ReadFile(tokenDir + "/" + agent + ".token")
	if err != nil {
		t.Fatalf("read token (was scripts/deploy-remote.sh run?): %v", err)
	}
	return strings.TrimSpace(string(b))
}

func connect(t *testing.T, agent string) *mcp.ClientSession {
	t.Helper()
	cmd := exec.Command(binary, "mcp")
	cmd.Env = append(os.Environ(), "SYSRAIL_TOKEN="+token(t, agent))
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil).
		Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("start sysrail mcp: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (bool, map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: structured content is not an object: %s", tool, b)
	}
	return res.IsError, m
}

func mustCall(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) map[string]any {
	t.Helper()
	isErr, m := call(t, cs, tool, args)
	if isErr {
		t.Fatalf("%s(%v) failed: %v", tool, args, m)
	}
	return m
}

func errorCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range res.Tools {
		names[tl.Name] = true
	}
	return names
}

// failDummy puts the dummy service into the failed state out of band, like a
// crashed production service.
func failDummy(t *testing.T) {
	t.Helper()
	run(t, "systemctl", "start", dummy)
	time.Sleep(300 * time.Millisecond)
	run(t, "systemctl", "kill", "--signal=KILL", dummy)
	for range 50 {
		if out, _ := exec.Command("systemctl", "is-failed", dummy).Output(); strings.TrimSpace(string(out)) == "failed" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("dummy service did not reach the failed state")
}

// TestDiagnoseAndRemediate is the spec §39 demo: find a failed service,
// read its logs, request a restart, get human approval, verify recovery.
func TestDiagnoseAndRemediate(t *testing.T) {
	failDummy(t)
	t.Cleanup(func() { exec.Command("systemctl", "stop", dummy).Run() })
	cs := connect(t, "e2e")

	failed := mustCall(t, cs, "service_list", map[string]any{"state": "failed"})
	found := false
	for _, s := range failed["services"].([]any) {
		found = found || s.(map[string]any)["name"] == dummy
	}
	if !found {
		t.Fatalf("failed services do not include %s: %v", dummy, failed)
	}
	status := mustCall(t, cs, "service_get_status", map[string]any{"name": "sysrail-test-dummy"})
	if status["active_state"] != "failed" || status["healthy"] != false {
		t.Fatalf("status: %v", status)
	}
	logs := mustCall(t, cs, "service_get_logs", map[string]any{"name": "sysrail-test-dummy", "lines": 20})
	text, _ := json.Marshal(logs)
	if strings.Contains(string(text), "hunter22") || !strings.Contains(string(text), "[REDACTED]") {
		t.Fatalf("logs were not redacted: %s", text)
	}
	mustCall(t, cs, "storage_get_status", nil)
	mustCall(t, cs, "network_get_connections", nil)

	pending := mustCall(t, cs, "service_restart", map[string]any{
		"name": "sysrail-test-dummy", "reason": "service is in failed state after SIGKILL",
	})
	id, _ := pending["request_id"].(string)
	if pending["status"] != "approval_required" || id == "" {
		t.Fatalf("restart must require approval: %v", pending)
	}
	if st := mustCall(t, cs, "request_get_status", map[string]any{"request_id": id}); st["status"] != "pending" {
		t.Fatalf("before approval: %v", st)
	}

	if list := run(t, binary, "approvals", "list"); !strings.Contains(list, id) {
		t.Fatalf("pending request not listed:\n%s", list)
	}
	if out := run(t, binary, "approvals", "approve", id, "--yes", "--note", "e2e"); !strings.Contains(out, "executed") {
		t.Fatalf("approve: %s", out)
	}

	st := mustCall(t, cs, "request_get_status", map[string]any{"request_id": id, "wait_seconds": 5})
	if st["status"] != "executed" || st["result"].(map[string]any)["active_state"] != "active" {
		t.Fatalf("after approval: %v", st)
	}
	if status := mustCall(t, cs, "service_get_status", map[string]any{"name": "sysrail-test-dummy"}); status["healthy"] != true {
		t.Fatalf("service did not recover: %v", status)
	}

	type record struct{ Event, Result, Actor string }
	var trail []record
	dec := json.NewDecoder(strings.NewReader(run(t, binary, "audit", "--json", "--request", id)))
	for dec.More() {
		var r record
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		trail = append(trail, r)
	}
	var got []string
	for _, r := range trail {
		got = append(got, r.Event+":"+r.Result)
	}
	if strings.Join(got, " ") != "request:approval_required approval:approved result:success" {
		t.Fatalf("audit trail: %v", got)
	}
	if !strings.HasPrefix(trail[1].Actor, "uid=0(root)") {
		t.Fatalf("approver identity not recorded from socket credentials: %q", trail[1].Actor)
	}
}

// TestDeniedActions is the spec §40 demo plus the other refusals agents must
// hit: policy denies, protected units, unscoped services and self-approval.
func TestDeniedActions(t *testing.T) {
	cs := connect(t, "e2e")
	names := toolNames(t, cs)
	for name := range names {
		for _, bad := range []string{"shell", "exec", "run", "command"} {
			if strings.Contains(name, bad) {
				t.Errorf("generic tool %q exposed", name)
			}
		}
	}
	if names["service_stop"] {
		t.Error("service_stop is denied by policy and must not be advertised")
	}
	cases := []struct {
		tool, name string
	}{
		{"service_restart", "ssh"},     // protected unit
		{"service_restart", "sysrail"}, // SysRail itself
		{"service_restart", "cron"},    // no rule for this unit
	}
	for _, c := range cases {
		isErr, m := call(t, cs, c.tool, map[string]any{"name": c.name})
		if !isErr || errorCode(m) != "PERMISSION_DENIED" {
			t.Errorf("%s %s: got %v, want PERMISSION_DENIED", c.tool, c.name, m)
		}
	}
	if isErr, m := call(t, cs, "service_restart", map[string]any{"name": "x; reboot"}); !isErr || errorCode(m) != "INVALID_ARGUMENT" {
		t.Errorf("injection attempt: %v", m)
	}

	pending := mustCall(t, cs, "service_start", map[string]any{"name": "sysrail-test-dummy"})
	id := pending["request_id"].(string)
	agent, err := client.New("/run/sysrail/agent.sock", token(t, "e2e"))
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := agent.Do(context.Background(), http.MethodPost, "/v1/requests/"+id+"/approve", map[string]any{}, nil); status == http.StatusOK {
		t.Fatal("an agent token approved its own request")
	}
	run(t, binary, "approvals", "deny", id, "--note", "e2e")
	if st := mustCall(t, cs, "request_get_status", map[string]any{"request_id": id}); st["status"] != "denied" {
		t.Fatalf("denied request: %v", st)
	}
}

func TestReadOnlyAgentSeesOnlyItsTools(t *testing.T) {
	cs := connect(t, "e2e-readonly")
	names := toolNames(t, cs)
	if !names["system_get_status"] || !names["service_get_status"] {
		t.Fatalf("read tools missing: %v", names)
	}
	for _, hidden := range []string{"service_restart", "service_get_logs", "storage_get_status"} {
		if names[hidden] {
			t.Errorf("%s advertised to read-only agent", hidden)
		}
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "service_restart", Arguments: map[string]any{"name": "sysrail-test-dummy"},
	}); err == nil {
		t.Fatal("hidden tool was callable")
	}
	gpu := mustCall(t, cs, "system_get_gpu_status", nil)
	t.Logf("GPU available: %v", gpu["available"])
}

// TestServiceFailureEvent checks that a crash is pushed to an agent that may
// read the service (spec §20).
func TestServiceFailureEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://127.0.0.1:9487/v1/events?types=service.failed", nil)
	req.Header.Set("Authorization", "Bearer "+token(t, "e2e"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("subscribe: %v %v", err, resp)
	}
	defer resp.Body.Close()
	time.Sleep(6 * time.Second) // let the watcher record a baseline

	failDummy(t)
	t.Cleanup(func() { exec.Command("systemctl", "reset-failed", dummy).Run() })
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, dummy) {
			t.Logf("received %s", line)
			return
		}
	}
	t.Fatalf("no service.failed event for %s: %v", dummy, sc.Err())
}

func TestSocketsAreNotOpenToOtherUsers(t *testing.T) {
	out, err := exec.Command("runuser", "-u", "nobody", "--", binary, "approvals", "list").CombinedOutput()
	if err == nil {
		t.Fatalf("nobody could use the admin socket:\n%s", out)
	}
	cmd := exec.Command("runuser", "-u", "nobody", "--", binary, "mcp")
	cmd.Env = append(os.Environ(), "SYSRAIL_TOKEN="+token(t, "e2e"))
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "not reachable") {
		t.Fatalf("nobody could reach the agent socket: %v\n%s", err, out)
	}
}

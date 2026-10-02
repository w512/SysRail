//go:build linux && e2e

package e2e

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/notify/smtptest"
)

// listenHTTP serves on a fixed port from deploy/test/config.yaml and reports
// request bodies (with the path) on the returned channel.
func listenHTTP(t *testing.T, addr, reply string) <-chan string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	ch := make(chan string, 32)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- r.URL.Path + " " + r.Header.Get("Title") + "\n" + string(b)
		io.WriteString(w, reply)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ch
}

// waitFor returns the first message on ch that contains want.
func waitFor(t *testing.T, name string, ch <-chan string, want string) string {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case m := <-ch:
			if strings.Contains(m, want) {
				return m
			}
		case <-deadline:
			t.Fatalf("%s: no notification containing %q", name, want)
		}
	}
}

// TestNotifications checks that a pending request reaches every channel
// type from inside the sandboxed daemon.
func TestNotifications(t *testing.T) {
	webhook := listenHTTP(t, "127.0.0.1:19801", "")
	ntfy := listenHTTP(t, "127.0.0.1:19802", `{"id":"x"}`)
	telegram := listenHTTP(t, "127.0.0.1:19803", `{"ok":true,"result":{}}`)
	smtp, err := smtptest.Start("127.0.0.1:19825")
	if err != nil {
		t.Fatal(err)
	}
	defer smtp.Close()
	mail := make(chan string, 32)
	go func() {
		for range smtp.Received() {
			msgs := smtp.Messages()
			mail <- msgs[len(msgs)-1].Data
		}
	}()

	cs := connect(t, "e2e")
	pending := mustCall(t, cs, "service_start", map[string]any{"name": "sysrail-test-dummy", "reason": "notify check"})
	id := pending["request_id"].(string)
	defer run(t, binary, "approvals", "deny", id)

	hook := waitFor(t, "webhook", webhook, id)
	var payload struct {
		Type    string `json:"type"`
		Request struct {
			ID, Agent, Reason string
		} `json:"request"`
	}
	json.Unmarshal([]byte(hook[strings.Index(hook, "\n")+1:]), &payload)
	if payload.Type != "request.pending" || payload.Request.Agent != "e2e" || payload.Request.Reason != "notify check" {
		t.Fatalf("webhook payload: %s", hook)
	}
	if m := waitFor(t, "ntfy", ntfy, id); !strings.HasPrefix(m, "/sysrail-e2e SysRail: approval needed on ") {
		t.Fatalf("ntfy: %s", m)
	}
	if m := waitFor(t, "telegram", telegram, id); !strings.HasPrefix(m, "/bot123:E2E/sendMessage") ||
		!strings.Contains(m, `"chat_id":"42"`) {
		t.Fatalf("telegram: %s", m)
	}
	if m := waitFor(t, "email", mail, id); !strings.Contains(m, "Subject: SysRail: approval needed") {
		t.Fatalf("email: %s", m)
	}

	if out := run(t, binary, "notify", "test"); strings.Count(out, "ok    ") != 4 {
		t.Fatalf("notify test:\n%s", out)
	}
}

// TestRetention checks that old records are archived and removed at daemon
// startup inside the sandbox (archive directory under StateDirectory).
func TestRetention(t *testing.T) {
	db := "/var/lib/sysrail/sysrail.db"
	run(t, "sqlite3", "-cmd", ".timeout 5000", db,
		`INSERT INTO audit_log (ts, event, agent, result) VALUES ('2025-01-01T00:00:00.000Z', 'request', 'e2e-ancient', 'started')`)
	run(t, "systemctl", "restart", "sysrail")

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command(binary, "audit", "--json", "--limit", "1000").Output()
		if strings.Contains(string(out), `"event": "retention"`) {
			if strings.Contains(string(out), "e2e-ancient") {
				t.Fatal("old record still in the audit log after retention")
			}
			archive := run(t, "sh", "-c", "zcat /var/lib/sysrail/archive/audit-*.jsonl.gz")
			if !strings.Contains(archive, "e2e-ancient") {
				t.Fatalf("old record missing from the archive:\n%s", archive)
			}
			perm := strings.TrimSpace(run(t, "sh", "-c", "stat -c '%a %U' /var/lib/sysrail/archive/audit-*.jsonl.gz | sort -u"))
			if perm != "600 sysrail" {
				t.Fatalf("archive permissions: %q", perm)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("no retention record after restart")
}

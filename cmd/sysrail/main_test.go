package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDispatch(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"token", "create"}, &out, &errOut); code != 0 {
		t.Fatalf("token create: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "token:        sysrail_") || !strings.Contains(out.String(), "token_sha256: ") {
		t.Fatalf("token output: %s", out.String())
	}
	errOut.Reset()
	if code := run([]string{"nope"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("unknown command: %d %s", code, errOut.String())
	}
	if code := run([]string{"approvals", "approve"}, &out, &errOut); code != 2 {
		t.Fatalf("approve without id: %d", code)
	}
}

func TestReasonLineIsSanitized(t *testing.T) {
	got := reasonLine("restart\x1b[2Jnow\n")
	if strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, "unverified") {
		t.Fatalf("got %q", got)
	}
}

func TestNotifyTest(t *testing.T) {
	received := make(chan string, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- string(b)
	}))
	defer hook.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("notifications:\n  webhooks:\n    - url: "+hook.URL+"\n  ntfy:\n    - url: http://127.0.0.1:1/topic\n"), 0o600)

	var out, errOut bytes.Buffer
	code := run([]string{"notify", "test", "--config", cfgPath}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "ok    webhook "+hook.URL) || !strings.Contains(out.String(), "FAIL  ntfy http://127.0.0.1:1/topic") {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
	if body := <-received; !strings.Contains(body, "test notification") {
		t.Fatalf("webhook body: %s", body)
	}
}

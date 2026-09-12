package main

import (
	"bytes"
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

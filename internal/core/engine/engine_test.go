package engine

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/policy"
	"github.com/w512/SysRail/internal/core/request"
	"github.com/w512/SysRail/internal/providers/fake"
	"github.com/w512/SysRail/internal/store/sqlite"
)

const testPolicy = `
version: 1
agents:
  agent:
    allow: [fake.read]
    ask: [fake.restart]
    resources:
      widget:
        auto: { fake.restart: allow }
        blocked: { fake.restart: deny }
  other:
    allow: [fake.read]
`

type harness struct {
	e     *Engine
	store *sqlite.Store
	fake  *fake.Provider
	clock *clock
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func compilePolicy(t *testing.T, reg *core.Registry, src string) *policy.Policy {
	t.Helper()
	f, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Compile(f, policy.Known{
		Agents:      map[string]bool{"agent": true, "other": true},
		Permissions: reg.Permissions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "sysrail.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	fp := fake.New()
	reg, err := core.NewRegistry(core.RegistryOptions{}, append(Builtins(store), fp.Capabilities()...)...)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Now()}
	e, err := New(Options{
		Registry: reg, Policy: compilePolicy(t, reg, testPolicy), Store: store,
		ApprovalTTL: 10 * time.Minute, Now: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{e: e, store: store, fake: fp, clock: clk}
}

func (h *harness) exec(t *testing.T, call Call) (*Outcome, *core.Error) {
	t.Helper()
	if call.Agent == "" {
		call.Agent = "agent"
	}
	out, err := h.e.Execute(context.Background(), call)
	if err != nil {
		var cerr *core.Error
		if !errors.As(err, &cerr) {
			t.Fatalf("non-structured error: %v", err)
		}
		return nil, cerr
	}
	return out, nil
}

func (h *harness) audit(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := h.store.List(context.Background(), audit.Filter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func wantCode(t *testing.T, err *core.Error, code core.Code) {
	t.Helper()
	if err == nil || err.Code != code {
		t.Fatalf("got error %v, want %s", err, code)
	}
}

func TestReadIsAuditedAndRedacted(t *testing.T) {
	h := newHarness(t)
	out, err := h.exec(t, Call{Session: "s1", Capability: "fake.status", Args: json.RawMessage(`{"value":"hi"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != StatusSuccess || strings.Contains(string(out.Result), "hunter22") ||
		!strings.Contains(string(out.Result), `"value":"hi"`) {
		t.Fatalf("outcome: %+v %s", out, out.Result)
	}
	recs := h.audit(t)
	if len(recs) != 2 {
		t.Fatalf("want 2 audit records, got %+v", recs)
	}
	req, res := recs[0], recs[1]
	if req.Event != audit.EventRequest || req.Result != audit.ResultStarted || req.Session != "s1" ||
		req.PolicyDecision != "allow" || req.ArgumentsHash == "" || string(req.Arguments) != `{"value":"hi"}` {
		t.Fatalf("request record: %+v", req)
	}
	if res.Event != audit.EventResult || res.Result != audit.ResultSuccess || res.ArgumentsHash != req.ArgumentsHash {
		t.Fatalf("result record: %+v", res)
	}
}

func TestRejectionsAreAudited(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		call   Call
		code   core.Code
		result string
	}{
		{Call{Capability: "fake.nope"}, core.CodeResourceNotFound, audit.ResultInvalid},
		{Call{Capability: "fake.slow", Args: json.RawMessage(`{"millis":"x"}`)}, core.CodeInvalidArgument, audit.ResultInvalid},
		{Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"-rf"}`)}, core.CodeInvalidArgument, audit.ResultInvalid},
		{Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"blocked"}`)}, core.CodePermissionDenied, audit.ResultDenied},
		{Call{Agent: "other", Capability: "fake.restart", Args: json.RawMessage(`{"name":"x"}`)}, core.CodePermissionDenied, audit.ResultDenied},
		{Call{Agent: "stranger", Capability: "fake.status"}, core.CodePermissionDenied, audit.ResultDenied},
		{Call{Capability: "fake.status", Reason: strings.Repeat("x", 501)}, core.CodeInvalidArgument, audit.ResultInvalid},
		{Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"x"}`), IdempotencyKey: "has space"}, core.CodeInvalidArgument, audit.ResultInvalid},
	}
	for i, tt := range tests {
		_, err := h.exec(t, tt.call)
		wantCode(t, err, tt.code)
		recs := h.audit(t)
		if len(recs) != i+1 || recs[i].Result != tt.result || recs[i].ErrorCode != string(tt.code) {
			t.Fatalf("case %d: audit %+v", i, recs[len(recs)-1])
		}
	}
	if h.fake.Restarts("blocked") != 0 || h.fake.Restarts("x") != 0 {
		t.Fatal("rejected mutation reached the provider")
	}
	if !strings.Contains(h.audit(t)[3].ErrorMessage, "fake.restart on blocked") {
		t.Fatalf("denial message: %q", h.audit(t)[3].ErrorMessage)
	}
}

func TestProviderRefusalIsAuditedAsDenied(t *testing.T) {
	h := newHarness(t)
	_, err := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"protected"}`)})
	wantCode(t, err, core.CodePermissionDenied)
	if recs := h.audit(t); recs[0].Result != audit.ResultDenied {
		t.Fatalf("audit result %q, want denied", recs[0].Result)
	}
}

func TestProviderErrors(t *testing.T) {
	h := newHarness(t)
	_, err := h.exec(t, Call{Capability: "fake.slow", Args: json.RawMessage(`{"millis":2000}`)})
	wantCode(t, err, core.CodeTimeout)
	if !err.Retryable {
		t.Fatal("timeouts must be retryable")
	}
	_, err = h.exec(t, Call{Capability: "fake.failure", Args: json.RawMessage(`{"code":"plain"}`)})
	wantCode(t, err, core.CodeExecutionFailed)
	if strings.Contains(err.Message, "abc123") {
		t.Fatalf("error message not redacted: %q", err.Message)
	}
	_, err = h.exec(t, Call{Capability: "fake.failure", Args: json.RawMessage(`{"code":"PROVIDER_UNAVAILABLE"}`)})
	wantCode(t, err, core.CodeProviderUnavailable)
	recs := h.audit(t)
	if last := recs[len(recs)-1]; last.Event != audit.EventResult || last.Result != audit.ResultError ||
		last.ErrorCode != string(core.CodeProviderUnavailable) {
		t.Fatalf("result record: %+v", last)
	}
}

func TestAllowedMutationIsTracked(t *testing.T) {
	h := newHarness(t)
	out, err := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"auto"}`), Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != StatusSuccess || out.RequestID == "" || h.fake.Restarts("auto") != 1 {
		t.Fatalf("outcome: %+v", out)
	}
	req, gerr := h.e.GetRequest(context.Background(), out.RequestID)
	if gerr != nil || req.Status != request.Executed || req.DecidedBy != "policy" || req.Reason != "test" {
		t.Fatalf("request: %v %+v", gerr, req)
	}
}

func TestApprovalFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	out, err := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":" w1 "}`), Reason: "stuck"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != StatusApprovalRequired || out.ExpiresAt == nil || h.fake.Restarts("w1") != 0 {
		t.Fatalf("outcome: %+v", out)
	}
	pending, _ := h.e.ListRequests(ctx, request.ListFilter{Status: request.Pending})
	if len(pending) != 1 || pending[0].Resource != "w1" || pending[0].Reason != "stuck" {
		t.Fatalf("pending: %+v", pending)
	}

	view := h.status(t, "agent", out.RequestID, 0)
	if view.Status != request.Pending {
		t.Fatalf("status before approval: %+v", view)
	}

	req, aerr := h.e.Approve(ctx, out.RequestID, "root", "ok")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if req.Status != request.Executed || req.DecidedBy != "root" || h.fake.Restarts("w1") != 1 {
		t.Fatalf("after approval: %+v", req)
	}
	view = h.status(t, "agent", out.RequestID, 0)
	if view.Status != request.Executed || !strings.Contains(string(view.Result), `"restarts":1`) {
		t.Fatalf("status after approval: %+v", view)
	}
	if _, err := h.e.Approve(ctx, out.RequestID, "root", ""); err == nil {
		t.Fatal("second approval must fail")
	}
	if h.fake.Restarts("w1") != 1 {
		t.Fatal("request executed twice")
	}

	var events []string
	for _, r := range h.audit(t) {
		if r.RequestID == out.RequestID {
			events = append(events, r.Event+":"+r.Result)
		}
	}
	want := "request:approval_required approval:approved result:success"
	if strings.Join(events, " ") != want {
		t.Fatalf("audit trail %v, want %s", events, want)
	}
}

func (h *harness) status(t *testing.T, agent, id string, wait int) RequestView {
	t.Helper()
	args, _ := json.Marshal(map[string]any{"request_id": id, "wait_seconds": wait})
	out, err := h.exec(t, Call{Agent: agent, Capability: "request.status", Args: args})
	if err != nil {
		t.Fatalf("request.status: %v", err)
	}
	var v RequestView
	if err := json.Unmarshal(out.Result, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRequestStatusIsScopedToCaller(t *testing.T) {
	h := newHarness(t)
	out, _ := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"w"}`)})
	args, _ := json.Marshal(map[string]any{"request_id": out.RequestID})
	_, err := h.exec(t, Call{Agent: "other", Capability: "request.status", Args: args})
	wantCode(t, err, core.CodeResourceNotFound)
}

func TestRequestStatusWaitsForDecision(t *testing.T) {
	h := newHarness(t)
	out, _ := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"w"}`)})
	go func() {
		time.Sleep(300 * time.Millisecond)
		h.e.Approve(context.Background(), out.RequestID, "root", "")
	}()
	start := time.Now()
	view := h.status(t, "agent", out.RequestID, 5)
	if view.Status != request.Executed || time.Since(start) > 3*time.Second {
		t.Fatalf("waited %s, got %+v", time.Since(start), view)
	}
}

func TestDenyAndExpiry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	denied, _ := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"a"}`)})
	req, err := h.e.Deny(ctx, denied.RequestID, "root", "not now")
	if err != nil || req.Status != request.Denied || req.DecisionNote != "not now" {
		t.Fatalf("deny: %v %+v", err, req)
	}
	_, err = h.e.Approve(ctx, denied.RequestID, "root", "")
	var cerr *core.Error
	if !errors.As(err, &cerr) || cerr.Code != core.CodeConflict {
		t.Fatalf("approve after deny: %v", err)
	}

	stale, _ := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"b"}`)})
	h.clock.advance(11 * time.Minute)
	_, err = h.e.Approve(ctx, stale.RequestID, "root", "")
	if !errors.As(err, &cerr) || cerr.Code != core.CodeConflict || !strings.Contains(cerr.Message, "expired") {
		t.Fatalf("approve after expiry: %v", err)
	}
	if h.fake.Restarts("a") != 0 || h.fake.Restarts("b") != 0 {
		t.Fatal("denied or expired request executed")
	}

	third, _ := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"c"}`)})
	h.clock.advance(11 * time.Minute)
	if n, err := h.e.ExpireStale(ctx); err != nil || n != 1 {
		t.Fatalf("expire stale: %d %v", n, err)
	}
	got, _ := h.e.GetRequest(ctx, third.RequestID)
	if got.Status != request.Expired || got.DecidedBy != "system" {
		t.Fatalf("expired request: %+v", got)
	}
}

func TestIdempotency(t *testing.T) {
	h := newHarness(t)
	call := Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"auto"}`), IdempotencyKey: "k-1"}
	first, err := h.exec(t, call)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.exec(t, call)
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != second.RequestID || string(first.Result) != string(second.Result) || h.fake.Restarts("auto") != 1 {
		t.Fatalf("retry was not idempotent: %+v %+v restarts=%d", first, second, h.fake.Restarts("auto"))
	}
	call.Args = json.RawMessage(`{"name":"other"}`)
	_, cerr := h.exec(t, call)
	wantCode(t, cerr, core.CodeConflict)

	pendingCall := Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"p"}`), IdempotencyKey: "k-2"}
	a, _ := h.exec(t, pendingCall)
	b, _ := h.exec(t, pendingCall)
	if a.Status != StatusApprovalRequired || a.RequestID != b.RequestID {
		t.Fatalf("pending retry: %+v %+v", a, b)
	}
}

func TestPolicyIsRecheckedOnApproval(t *testing.T) {
	h := newHarness(t)
	out, _ := h.exec(t, Call{Capability: "fake.restart", Args: json.RawMessage(`{"name":"w"}`)})
	h.e.SetPolicy(compilePolicy(t, h.e.Registry(), "version: 1\nagents:\n  agent:\n    deny: [fake.restart]\n"))
	req, err := h.e.Approve(context.Background(), out.RequestID, "root", "")
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != request.Failed || req.Error == nil || req.Error.Code != core.CodePermissionDenied {
		t.Fatalf("request: %+v", req)
	}
	if h.fake.Restarts("w") != 0 {
		t.Fatal("request executed despite policy change")
	}
}

type brokenAudit struct{ *sqlite.Store }

func (brokenAudit) Append(context.Context, *audit.Record) error { return errors.New("disk full") }

func TestAuditFailureRefusesExecution(t *testing.T) {
	h := newHarness(t)
	e, err := New(Options{Registry: h.e.Registry(), Policy: h.e.Policy(), Store: brokenAudit{h.store}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Execute(context.Background(), Call{Agent: "agent", Capability: "fake.restart", Args: json.RawMessage(`{"name":"auto"}`)})
	var cerr *core.Error
	if !errors.As(err, &cerr) || cerr.Code != core.CodeExecutionFailed || !strings.Contains(cerr.Message, "audit") {
		t.Fatalf("got %v", err)
	}
	if h.fake.Restarts("auto") != 0 {
		t.Fatal("mutation ran without an audit record")
	}
	if reqs, _ := h.store.ListRequests(context.Background(), request.ListFilter{}); len(reqs) != 0 {
		t.Fatalf("request created without audit: %+v", reqs)
	}
}

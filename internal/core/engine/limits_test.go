package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
)

func limitedEngine(t *testing.T, h *harness, limits map[string]Limits) *Engine {
	t.Helper()
	e, err := New(Options{
		Registry: h.e.Registry(), Policy: h.e.Policy(), Store: h.store, Now: h.clock.now,
		ApprovalTTL: 10 * time.Minute,
		Limits:      func(agent string) Limits { return limits[agent] },
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func call(e *Engine, agent, capability, args string) (*Outcome, *core.Error) {
	out, err := e.Execute(context.Background(), Call{Agent: agent, Capability: capability, Args: json.RawMessage(args)})
	if err != nil {
		return nil, core.AsError(err)
	}
	return out, nil
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t)
	e := limitedEngine(t, h, map[string]Limits{"agent": {CallsPerMinute: 60, Burst: 3}})
	for i := range 3 {
		if _, err := call(e, "agent", "fake.status", `{}`); err != nil {
			t.Fatalf("call %d within burst: %v", i, err)
		}
	}
	_, err := call(e, "agent", "fake.status", `{}`)
	if err == nil || err.Code != core.CodeRateLimited || !err.Retryable || err.Details["retry_after_seconds"] != 1 {
		t.Fatalf("over the limit: %+v", err)
	}
	if _, err := call(e, "other", "fake.status", `{}`); err != nil {
		t.Fatalf("other agents have their own budget: %v", err)
	}
	h.clock.advance(time.Second)
	if _, err := call(e, "agent", "fake.status", `{}`); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

func TestRateLimitedCallsAreAuditedWithoutFlooding(t *testing.T) {
	h := newHarness(t)
	e := limitedEngine(t, h, map[string]Limits{"agent": {CallsPerMinute: 6, Burst: 1}})
	call(e, "agent", "fake.status", `{}`)
	before := len(h.audit(t))
	for range 50 {
		call(e, "agent", "fake.nope", `{}`)
	}
	limited := func() []audit.Record {
		var out []audit.Record
		for _, r := range h.audit(t)[before:] {
			if r.Result == audit.ResultRateLimited {
				out = append(out, r)
			}
		}
		return out
	}
	recs := limited()
	if len(h.audit(t))-before != 1 || len(recs) != 1 || recs[0].Capability != "fake.nope" ||
		recs[0].ErrorCode != string(core.CodeRateLimited) {
		t.Fatalf("50 rejected calls in a burst must produce one record, got %+v", h.audit(t)[before:])
	}

	h.clock.advance(11 * time.Second)
	if _, err := call(e, "agent", "fake.status", `{}`); err != nil {
		t.Fatal(err)
	}
	recs = limited()
	if len(recs) != 2 || recs[1].Event != audit.EventRateLimit ||
		!strings.Contains(recs[1].Note, "49 calls were rejected by the rate limit") {
		t.Fatalf("summary after recovery: %+v", recs)
	}

	// The summary counts as this interval's record, so further rejections
	// within 10 seconds are only counted until the next flush.
	call(e, "agent", "fake.status", `{}`)
	call(e, "agent", "fake.status", `{}`)
	if recs = limited(); len(recs) != 2 {
		t.Fatalf("at most one record per agent per interval: %+v", recs)
	}
	e.FlushRateLimits(context.Background(), true)
	if recs = limited(); len(recs) != 3 || !strings.Contains(recs[2].Note, "2 calls were rejected") {
		t.Fatalf("forced flush: %+v", recs)
	}
}

func TestMaxPending(t *testing.T) {
	h := newHarness(t)
	e := limitedEngine(t, h, map[string]Limits{"agent": {MaxPending: 2}})
	ctx := context.Background()
	first, _ := e.Execute(ctx, Call{Agent: "agent", Capability: "fake.restart", Args: json.RawMessage(`{"name":"a"}`), IdempotencyKey: "k-a"})
	if _, err := call(e, "agent", "fake.restart", `{"name":"b"}`); err != nil {
		t.Fatal(err)
	}
	_, err := call(e, "agent", "fake.restart", `{"name":"c"}`)
	if err == nil || err.Code != core.CodeRateLimited || !strings.Contains(err.Message, "2 requests waiting for approval") {
		t.Fatalf("third pending request: %+v", err)
	}
	recs := h.audit(t)
	if last := recs[len(recs)-1]; last.Result != audit.ResultRateLimited || last.Resource != "c" {
		t.Fatalf("pending-limit refusal must be audited: %+v", last)
	}

	replay, rerr := e.Execute(ctx, Call{Agent: "agent", Capability: "fake.restart", Args: json.RawMessage(`{"name":"a"}`), IdempotencyKey: "k-a"})
	if rerr != nil || replay.RequestID != first.RequestID {
		t.Fatalf("a retry of an existing pending request must not count: %v %+v", rerr, replay)
	}
	if out, err := call(e, "agent", "fake.restart", `{"name":"auto"}`); err != nil || out.Status != StatusSuccess {
		t.Fatalf("allowed mutations never wait for approval and are not capped: %v %+v", err, out)
	}

	e.Deny(ctx, first.RequestID, "root", "")
	if _, err := call(e, "agent", "fake.restart", `{"name":"c"}`); err != nil {
		t.Fatalf("after a decision there is room again: %v", err)
	}
	h.clock.advance(11 * time.Minute)
	if _, err := call(e, "agent", "fake.restart", `{"name":"d"}`); err != nil {
		t.Fatalf("expired requests must not count: %v", err)
	}
}

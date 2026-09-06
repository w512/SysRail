package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/request"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sysrail.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestOpenCreatesPrivateFileAndIsReentrant(t *testing.T) {
	s, path := open(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("database mode %o, want 600", perm)
	}
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.Close()
}

func TestAuditAppendListAndImmutability(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for i, agent := range []string{"a", "b", "a"} {
		r := &audit.Record{Event: audit.EventRequest, Agent: agent, Capability: "system.status",
			Result: audit.ResultStarted, Arguments: json.RawMessage(`{"n":1}`), DurationMS: int64(i)}
		if err := s.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
		if r.ID == 0 {
			t.Fatal("record id not set")
		}
	}
	all, err := s.List(ctx, audit.Filter{})
	if err != nil || len(all) != 3 || all[0].ID > all[2].ID {
		t.Fatalf("list: %v %+v", err, all)
	}
	if string(all[0].Arguments) != `{"n":1}` || all[0].Time.IsZero() {
		t.Fatalf("record round trip: %+v", all[0])
	}
	newest, _ := s.List(ctx, audit.Filter{Limit: 1})
	if len(newest) != 1 || newest[0].ID != all[2].ID {
		t.Fatalf("newest: %+v", newest)
	}
	byAgent, _ := s.List(ctx, audit.Filter{Agent: "a"})
	if len(byAgent) != 2 {
		t.Fatalf("by agent: %d", len(byAgent))
	}
	after, _ := s.List(ctx, audit.Filter{AfterID: all[0].ID})
	if len(after) != 2 || after[0].ID != all[1].ID {
		t.Fatalf("after: %+v", after)
	}
	for _, q := range []string{`UPDATE audit_log SET result = 'x'`, `DELETE FROM audit_log`} {
		if _, err := s.db.Exec(q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: got %v, want append-only error", q, err)
		}
	}
}

func newRequest(id, key string) *request.Request {
	exp := time.Now().Add(time.Minute)
	return &request.Request{
		ID: id, Agent: "opencode", Capability: "service.restart", Resource: "nginx.service",
		Args: json.RawMessage(`{"name":"nginx.service"}`), ArgsHash: "h", Risk: core.RiskLow,
		Status: request.Pending, IdempotencyKey: key, CreatedAt: time.Now(), ExpiresAt: &exp,
	}
}

func TestRequestLifecycle(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateRequest(ctx, newRequest("req_1", "k1")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRequest(ctx, newRequest("req_2", "k1")); !errors.Is(err, request.ErrDuplicateKey) {
		t.Fatalf("duplicate key: %v", err)
	}
	if err := s.CreateRequest(ctx, newRequest("req_3", "")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRequest(ctx, newRequest("req_4", "")); err != nil {
		t.Fatalf("empty keys must not collide: %v", err)
	}

	got, err := s.FindByIdempotencyKey(ctx, "opencode", "k1")
	if err != nil || got.ID != "req_1" || got.ExpiresAt == nil {
		t.Fatalf("find by key: %v %+v", err, got)
	}
	if _, err := s.GetRequest(ctx, "nope"); !errors.Is(err, request.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	if err := s.Transition(ctx, "req_1", request.Pending, request.Approved, request.Update{DecidedBy: "root"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(ctx, "req_1", request.Pending, request.Denied, request.Update{}); !errors.Is(err, request.ErrStateConflict) {
		t.Fatalf("second decision: %v", err)
	}
	if err := s.Transition(ctx, "req_1", request.Approved, request.Executed,
		request.Update{Result: json.RawMessage(`{"ok":true}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(ctx, "req_1", request.Executed, request.Failed, request.Update{}); err == nil {
		t.Fatal("illegal transition accepted")
	}
	if err := s.Transition(ctx, "nope", request.Pending, request.Denied, request.Update{}); !errors.Is(err, request.ErrNotFound) {
		t.Fatalf("missing transition: %v", err)
	}
	got, _ = s.GetRequest(ctx, "req_1")
	if got.Status != request.Executed || got.DecidedBy != "root" || got.DecidedAt == nil ||
		got.CompletedAt == nil || string(got.Result) != `{"ok":true}` {
		t.Fatalf("after execution: %+v", got)
	}

	if err := s.Transition(ctx, "req_3", request.Pending, request.Approved, request.Update{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(ctx, "req_3", request.Approved, request.Failed,
		request.Update{Error: core.Errorf(core.CodeTimeout, "slow")}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRequest(ctx, "req_3")
	if got.Error == nil || got.Error.Code != core.CodeTimeout || !got.Error.Retryable {
		t.Fatalf("error round trip: %+v", got.Error)
	}

	pending, _ := s.ListRequests(ctx, request.ListFilter{Status: request.Pending})
	if len(pending) != 1 || pending[0].ID != "req_4" {
		t.Fatalf("pending: %+v", pending)
	}
	expired, _ := s.ExpiredPending(ctx, time.Now().Add(2*time.Minute))
	if len(expired) != 1 || expired[0].ID != "req_4" {
		t.Fatalf("expired: %+v", expired)
	}
	if none, _ := s.ExpiredPending(ctx, time.Now()); len(none) != 0 {
		t.Fatalf("nothing should be expired yet: %+v", none)
	}
}

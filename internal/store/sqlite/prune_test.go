package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/request"
)

func TestPruneBatch(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	now := time.Now()
	old := now.Add(-100 * 24 * time.Hour)
	for i, ts := range []time.Time{old, old.Add(time.Minute), now} {
		if err := s.Append(ctx, &audit.Record{Time: ts, Event: audit.EventRequest, Result: audit.ResultStarted,
			Agent: "a", DurationMS: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(id string, created time.Time, status request.Status) {
		r := newRequest(id, "")
		r.CreatedAt, r.Status = created, status
		if err := s.CreateRequest(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	mk("req_old_done", old, request.Executed)
	mk("req_old_pending", old, request.Pending)
	mk("req_old_running", old, request.Approved)
	mk("req_new_done", now, request.Executed)

	cutoff := now.Add(-90 * 24 * time.Hour)
	if _, _, err := s.PruneBatch(ctx, cutoff, 10, func([]audit.Record, []request.Request) error {
		return errors.New("disk full")
	}); err == nil {
		t.Fatal("archive failure must abort the prune")
	}
	if recs, _ := s.List(ctx, audit.Filter{}); len(recs) != 3 {
		t.Fatalf("records deleted despite archive failure: %d left", len(recs))
	}

	var archived []audit.Record
	var archivedReqs []request.Request
	archive := func(r []audit.Record, q []request.Request) error {
		archived, archivedReqs = append(archived, r...), append(archivedReqs, q...)
		return nil
	}
	n, m, err := s.PruneBatch(ctx, cutoff, 1, archive)
	if err != nil || n != 1 || m != 1 {
		t.Fatalf("first batch: %d %d %v", n, m, err)
	}
	n, m, err = s.PruneBatch(ctx, cutoff, 1, archive)
	if err != nil || n != 1 || m != 0 {
		t.Fatalf("second batch: %d %d %v", n, m, err)
	}
	if n, m, err = s.PruneBatch(ctx, cutoff, 1, archive); n != 0 || m != 0 || err != nil {
		t.Fatalf("nothing left to prune: %d %d %v", n, m, err)
	}

	if len(archived) != 2 || archived[0].DurationMS != 0 || archived[1].DurationMS != 1 {
		t.Fatalf("archived records: %+v", archived)
	}
	if len(archivedReqs) != 1 || archivedReqs[0].ID != "req_old_done" {
		t.Fatalf("archived requests: %+v (pending and running requests must stay)", archivedReqs)
	}
	recs, _ := s.List(ctx, audit.Filter{})
	if len(recs) != 1 || recs[0].DurationMS != 2 {
		t.Fatalf("remaining records: %+v", recs)
	}
	for _, id := range []string{"req_old_pending", "req_old_running", "req_new_done"} {
		if _, err := s.GetRequest(ctx, id); err != nil {
			t.Errorf("%s was pruned: %v", id, err)
		}
	}

	if _, err := s.db.Exec(`DELETE FROM audit_log`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("plain deletes must still be refused: %v", err)
	}
}

func TestNoteRoundTrip(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.Append(ctx, &audit.Record{Event: audit.EventRetention, Result: audit.ResultPruned, Note: "removed 3"}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := s.List(ctx, audit.Filter{}); recs[0].Note != "removed 3" {
		t.Fatalf("note: %+v", recs[0])
	}
}

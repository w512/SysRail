package retention

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/request"
	"github.com/w512/SysRail/internal/store/sqlite"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func seed(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "sysrail.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	for i, age := range []time.Duration{200, 120, 91, 30, 1} {
		ts := now.Add(-age * 24 * time.Hour)
		if err := s.Append(ctx, &audit.Record{Time: ts, Event: audit.EventRequest, Agent: "a",
			Result: audit.ResultStarted, Arguments: json.RawMessage(`{"n":1}`), DurationMS: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	old := &request.Request{ID: "req_old", Agent: "a", Capability: "service.restart", Resource: "x.service",
		Args: json.RawMessage(`{"name":"x.service","password":"hunter22"}`), ArgsHash: "h", Risk: core.RiskLow,
		Status: request.Executed, CreatedAt: now.Add(-100 * 24 * time.Hour)}
	if err := s.CreateRequest(ctx, old); err != nil {
		t.Fatal(err)
	}
	return s
}

func readArchive(t *testing.T, path string) []Line {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []Line
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		var l Line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		out = append(out, l)
	}
	return out
}

func TestRunArchivesAndPrunes(t *testing.T) {
	s := seed(t)
	dir := filepath.Join(t.TempDir(), "archive")
	res, err := Run(context.Background(), Options{Store: s, Days: 90, ArchiveDir: dir, BatchSize: 2,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 3 || res.Requests != 1 || len(res.Files) != 2 {
		t.Fatalf("result: %+v", res)
	}
	var lines []Line
	for _, f := range res.Files {
		fi, err := os.Stat(f)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi.Mode(), err)
		}
		lines = append(lines, readArchive(t, f)...)
	}
	if len(lines) != 4 || lines[0].Type != "audit" || lines[0].Record.DurationMS != 0 {
		t.Fatalf("archive lines: %+v", lines)
	}
	var req *request.Request
	for _, l := range lines {
		if l.Type == "request" {
			req = l.Request
		}
	}
	if req == nil || req.ID != "req_old" || strings.Contains(string(req.Args), "hunter22") {
		t.Fatalf("archived request (arguments must be redacted): %+v", req)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}

	recs, _ := s.List(context.Background(), audit.Filter{})
	if len(recs) != 3 {
		t.Fatalf("want 2 recent records + retention summary, got %+v", recs)
	}
	summary := recs[2]
	if summary.Event != audit.EventRetention || summary.Result != audit.ResultPruned || summary.Actor != "system" ||
		!strings.Contains(summary.Note, "removed 3 audit records and 1 finished requests older than 2026-07-04") ||
		!strings.Contains(summary.Note, "archived to 2 files") {
		t.Fatalf("summary: %+v", summary)
	}

	res, err = Run(context.Background(), Options{Store: s, Days: 90, ArchiveDir: dir, Now: func() time.Time { return now }})
	if err != nil || res.Records != 0 || len(res.Files) != 0 {
		t.Fatalf("second run: %+v %v", res, err)
	}
	if recs, _ := s.List(context.Background(), audit.Filter{}); len(recs) != 3 {
		t.Fatal("a run that removed nothing must not write a summary")
	}
}

func TestRunWithoutArchive(t *testing.T) {
	s := seed(t)
	res, err := Run(context.Background(), Options{Store: s, Days: 90, Now: func() time.Time { return now }})
	if err != nil || res.Records != 3 || len(res.Files) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	recs, _ := s.List(context.Background(), audit.Filter{})
	if !strings.Contains(recs[len(recs)-1].Note, "archiving is disabled") {
		t.Fatalf("summary: %+v", recs[len(recs)-1])
	}
}

func TestRunDisabled(t *testing.T) {
	s := seed(t)
	if res, err := Run(context.Background(), Options{Store: s, Days: 0, Now: func() time.Time { return now }}); err != nil || res.Records != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if recs, _ := s.List(context.Background(), audit.Filter{}); len(recs) != 5 {
		t.Fatalf("retention 0 must keep everything, have %d", len(recs))
	}
}

func TestArchiveFailureKeepsRecords(t *testing.T) {
	s := seed(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	_, err := Run(context.Background(), Options{Store: s, Days: 90, ArchiveDir: dir, Now: func() time.Time { return now }})
	if err == nil {
		t.Fatal("unwritable archive directory must fail")
	}
	recs, _ := s.List(context.Background(), audit.Filter{})
	if len(recs) != 6 || recs[5].Result != audit.ResultError {
		t.Fatalf("records must stay and the failure must be audited: %+v", recs)
	}
}

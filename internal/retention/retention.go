// Package retention removes audit records and finished requests older than
// the configured retention period, writing them to compressed JSON Lines
// archives first.
package retention

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/redact"
	"github.com/w512/SysRail/internal/core/request"
)

// Store is the storage retention needs.
type Store interface {
	PruneBatch(ctx context.Context, cutoff time.Time, limit int,
		archive func([]audit.Record, []request.Request) error) (int, int, error)
	Append(ctx context.Context, r *audit.Record) error
}

// Options configures retention.
type Options struct {
	Store Store
	// Days to keep; 0 keeps everything.
	Days int
	// ArchiveDir receives removed rows as .jsonl.gz files; empty disables
	// archiving and rows are simply deleted.
	ArchiveDir string
	// BatchSize bounds each transaction. Default 5000.
	BatchSize int
	Now       func() time.Time
	Log       *slog.Logger
}

// Result summarizes one run.
type Result struct {
	Cutoff   time.Time
	Records  int
	Requests int
	Files    []string
}

// Line is one line of an archive file.
type Line struct {
	Type    string           `json:"type"` // "audit" or "request"
	Record  *audit.Record    `json:"record,omitempty"`
	Request *request.Request `json:"request,omitempty"`
}

func (o *Options) defaults() {
	if o.BatchSize <= 0 {
		o.BatchSize = 5000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
}

// Run prunes everything older than the retention period and records what it
// removed in the audit log.
func Run(ctx context.Context, o Options) (Result, error) {
	o.defaults()
	if o.Days <= 0 {
		return Result{}, nil
	}
	now := o.Now()
	res := Result{Cutoff: now.Add(-time.Duration(o.Days) * 24 * time.Hour)}
	if o.ArchiveDir != "" {
		if err := os.MkdirAll(o.ArchiveDir, 0o700); err != nil {
			return res, fmt.Errorf("create archive directory: %w", err)
		}
	}
	stamp := now.UTC().Format("20060102T150405Z")
	for batch := 1; ; batch++ {
		var file string
		n, m, err := o.Store.PruneBatch(ctx, res.Cutoff, o.BatchSize, func(recs []audit.Record, reqs []request.Request) error {
			if o.ArchiveDir == "" {
				return nil
			}
			file = filepath.Join(o.ArchiveDir, fmt.Sprintf("audit-%s-%03d.jsonl.gz", stamp, batch))
			return writeArchive(file, recs, reqs)
		})
		if err != nil {
			err = fmt.Errorf("prune: %w", err)
			o.record(ctx, res, err)
			return res, err
		}
		if n == 0 && m == 0 {
			break
		}
		res.Records += n
		res.Requests += m
		if file != "" {
			res.Files = append(res.Files, file)
		}
	}
	if res.Records > 0 || res.Requests > 0 {
		o.record(ctx, res, nil)
	}
	return res, nil
}

// record writes a retention summary to the audit log so that the removal of
// old records is itself audited.
func (o *Options) record(ctx context.Context, res Result, runErr error) {
	if res.Records == 0 && res.Requests == 0 && runErr == nil {
		return
	}
	note := fmt.Sprintf("removed %d audit records and %d finished requests older than %s",
		res.Records, res.Requests, res.Cutoff.UTC().Format(time.RFC3339))
	switch {
	case len(res.Files) == 1:
		note += "; archived to " + res.Files[0]
	case len(res.Files) > 1:
		note += fmt.Sprintf("; archived to %d files: %s ... %s", len(res.Files), res.Files[0], filepath.Base(res.Files[len(res.Files)-1]))
	case o.ArchiveDir == "":
		note += "; archiving is disabled"
	}
	rec := &audit.Record{Event: audit.EventRetention, Result: audit.ResultPruned, Actor: "system", Note: note}
	if runErr != nil {
		rec.Result, rec.ErrorCode, rec.ErrorMessage = audit.ResultError, "EXECUTION_FAILED", runErr.Error()
	}
	if err := o.Store.Append(context.WithoutCancel(ctx), rec); err != nil {
		o.Log.Error("audit write failed for retention summary", "error", err)
	}
}

// writeArchive writes rows to path atomically: a temporary file is fully
// written and synced before it is renamed into place.
func writeArchive(path string, recs []audit.Record, reqs []request.Request) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	zw := gzip.NewWriter(f)
	enc := json.NewEncoder(zw)
	for i := range recs {
		if err := enc.Encode(Line{Type: "audit", Record: &recs[i]}); err != nil {
			return err
		}
	}
	for i := range reqs {
		r := reqs[i]
		// Arguments were kept unredacted only so approved requests could run.
		r.Args = redact.JSON(r.Args)
		if err := enc.Encode(Line{Type: "request", Request: &r}); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Loop runs retention now and then every interval until ctx is canceled.
func Loop(ctx context.Context, o Options, interval time.Duration) {
	o.defaults()
	if o.Days <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		res, err := Run(ctx, o)
		switch {
		case err != nil:
			o.Log.Error("audit retention failed", "error", err)
		case res.Records > 0 || res.Requests > 0:
			o.Log.Info("audit retention", "records", res.Records, "requests", res.Requests,
				"cutoff", res.Cutoff, "archives", len(res.Files))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

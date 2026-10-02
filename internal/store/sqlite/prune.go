package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/request"
)

// PruneBatch removes up to limit audit records written before cutoff and up
// to limit finished requests (denied, expired, executed, failed) created
// before cutoff. archive receives the selected rows first, inside the same
// transaction; if it returns an error nothing is deleted. It returns how many
// audit records and requests were removed; zero for both means done.
func (s *Store) PruneBatch(ctx context.Context, cutoff time.Time, limit int,
	archive func([]audit.Record, []request.Request) error) (int, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `SELECT `+auditColumns+` FROM audit_log WHERE ts < ? ORDER BY id LIMIT ?`,
		formatTime(cutoff), limit)
	if err != nil {
		return 0, 0, fmt.Errorf("select old audit records: %w", err)
	}
	records, err := scanAuditRows(rows)
	rows.Close()
	if err != nil {
		return 0, 0, err
	}

	reqRows, err := tx.QueryContext(ctx, `SELECT `+requestColumns+` FROM requests
		WHERE created_at < ? AND status IN (?, ?, ?, ?) ORDER BY created_at LIMIT ?`,
		formatTime(cutoff), string(request.Denied), string(request.Expired), string(request.Executed),
		string(request.Failed), limit)
	if err != nil {
		return 0, 0, fmt.Errorf("select old requests: %w", err)
	}
	var reqs []request.Request
	for reqRows.Next() {
		r, err := scanRequest(reqRows)
		if err != nil {
			reqRows.Close()
			return 0, 0, err
		}
		reqs = append(reqs, *r)
	}
	reqRows.Close()
	if err := reqRows.Err(); err != nil {
		return 0, 0, err
	}
	if len(records) == 0 && len(reqs) == 0 {
		return 0, 0, nil
	}

	if err := archive(records, reqs); err != nil {
		return 0, 0, fmt.Errorf("archive: %w", err)
	}

	if len(records) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_prune_guard (active) VALUES (1)`); err != nil {
			return 0, 0, err
		}
		ids := make([]any, len(records))
		for i, r := range records {
			ids[i] = r.ID
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE id IN (`+placeholders(len(ids))+`)`, ids...); err != nil {
			return 0, 0, fmt.Errorf("delete audit records: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM audit_prune_guard`); err != nil {
			return 0, 0, err
		}
	}
	if len(reqs) > 0 {
		ids := make([]any, len(reqs))
		for i, r := range reqs {
			ids[i] = r.ID
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM requests WHERE id IN (`+placeholders(len(ids))+`)`, ids...); err != nil {
			return 0, 0, fmt.Errorf("delete requests: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return len(records), len(reqs), nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

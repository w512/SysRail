// Package sqlite persists the audit log and tracked requests in SQLite
// (pure Go driver, no cgo).
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/request"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Fixed-width UTC timestamps sort correctly as text.
const tsFormat = "2006-01-02T15:04:05.000Z"

// Store implements audit.Log and request.Store.
type Store struct {
	db *sql.DB
}

var (
	_ audit.Log     = (*Store)(nil)
	_ request.Store = (*Store)(nil)
)

// Open opens (creating if needed, with mode 0600) the database at path and
// applies pending migrations.
func Open(path string) (*Store, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("database path must not contain '?' or '#'")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	f.Close()
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks that the database is usable.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migrate: bad migration name %s", name)
		}
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&exists); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if exists > 0 {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate %s: %w", base, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			version, formatTime(time.Now())); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate %s: %w", base, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate %s: %w", base, err)
		}
	}
	return nil
}

// Append implements audit.Log.
func (s *Store) Append(ctx context.Context, r *audit.Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit_log
		(ts, event, agent, session, capability, resource, arguments_hash, arguments,
		 policy_decision, policy_rule, request_id, result, error_code, error_message, duration_ms, actor, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(r.Time), r.Event, r.Agent, r.Session, r.Capability, r.Resource, r.ArgumentsHash,
		string(r.Arguments), r.PolicyDecision, r.PolicyRule, r.RequestID, r.Result, r.ErrorCode,
		r.ErrorMessage, r.DurationMS, r.Actor, r.Note)
	if err != nil {
		return fmt.Errorf("append audit record: %w", err)
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

// List implements audit.Log.
func (s *Store) List(ctx context.Context, f audit.Filter) ([]audit.Record, error) {
	limit := clampLimit(f.Limit)
	var where []string
	var args []any
	if f.Agent != "" {
		where, args = append(where, "agent = ?"), append(args, f.Agent)
	}
	if f.Capability != "" {
		where, args = append(where, "capability = ?"), append(args, f.Capability)
	}
	if f.RequestID != "" {
		where, args = append(where, "request_id = ?"), append(args, f.RequestID)
	}
	order := "DESC"
	if f.AfterID > 0 {
		where, args = append(where, "id > ?"), append(args, f.AfterID)
		order = "ASC"
	}
	q := `SELECT ` + auditColumns + ` FROM audit_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id " + order + " LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	defer rows.Close()
	out, err := scanAuditRows(rows)
	if err != nil {
		return nil, err
	}
	if order == "DESC" {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, nil
}

const auditColumns = `id, ts, event, agent, session, capability, resource, arguments_hash, arguments,
	policy_decision, policy_rule, request_id, result, error_code, error_message, duration_ms, actor, note`

func scanAuditRows(rows *sql.Rows) ([]audit.Record, error) {
	var out []audit.Record
	for rows.Next() {
		var r audit.Record
		var ts, arguments string
		if err := rows.Scan(&r.ID, &ts, &r.Event, &r.Agent, &r.Session, &r.Capability, &r.Resource,
			&r.ArgumentsHash, &arguments, &r.PolicyDecision, &r.PolicyRule, &r.RequestID, &r.Result,
			&r.ErrorCode, &r.ErrorMessage, &r.DurationMS, &r.Actor, &r.Note); err != nil {
			return nil, err
		}
		r.Time = parseTime(ts)
		if arguments != "" {
			r.Arguments = json.RawMessage(arguments)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateRequest implements request.Store.
func (s *Store) CreateRequest(ctx context.Context, r *request.Request) error {
	errJSON, err := marshalError(r.Error)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO requests
		(id, agent, session, capability, resource, args, args_hash, reason, risk, status, policy_rule,
		 idempotency_key, created_at, expires_at, decided_at, decided_by, decision_note, completed_at, result, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Agent, r.Session, r.Capability, r.Resource, string(r.Args), r.ArgsHash, r.Reason,
		string(r.Risk), string(r.Status), r.PolicyRule, nullString(r.IdempotencyKey), formatTime(r.CreatedAt),
		nullTime(r.ExpiresAt), nullTime(r.DecidedAt), r.DecidedBy, r.DecisionNote, nullTime(r.CompletedAt),
		nullBytes(r.Result), errJSON)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: requests.agent, requests.idempotency_key") {
			return request.ErrDuplicateKey
		}
		return fmt.Errorf("create request: %w", err)
	}
	return nil
}

const requestColumns = `id, agent, session, capability, resource, args, args_hash, reason, risk, status,
	policy_rule, idempotency_key, created_at, expires_at, decided_at, decided_by, decision_note,
	completed_at, result, error`

type scanner interface{ Scan(dest ...any) error }

func scanRequest(row scanner) (*request.Request, error) {
	var r request.Request
	var args, risk, status, created string
	var idemKey, expires, decided, completed, result, errJSON sql.NullString
	if err := row.Scan(&r.ID, &r.Agent, &r.Session, &r.Capability, &r.Resource, &args, &r.ArgsHash,
		&r.Reason, &risk, &status, &r.PolicyRule, &idemKey, &created, &expires, &decided, &r.DecidedBy,
		&r.DecisionNote, &completed, &result, &errJSON); err != nil {
		return nil, err
	}
	r.Args = json.RawMessage(args)
	r.Risk = core.Risk(risk)
	r.Status = request.Status(status)
	r.IdempotencyKey = idemKey.String
	r.CreatedAt = parseTime(created)
	r.ExpiresAt = parseNullTime(expires)
	r.DecidedAt = parseNullTime(decided)
	r.CompletedAt = parseNullTime(completed)
	if result.Valid {
		r.Result = json.RawMessage(result.String)
	}
	if errJSON.Valid {
		r.Error = &core.Error{}
		if err := json.Unmarshal([]byte(errJSON.String), r.Error); err != nil {
			return nil, fmt.Errorf("decode request error: %w", err)
		}
	}
	return &r, nil
}

// GetRequest implements request.Store.
func (s *Store) GetRequest(ctx context.Context, id string) (*request.Request, error) {
	r, err := scanRequest(s.db.QueryRowContext(ctx, `SELECT `+requestColumns+` FROM requests WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, request.ErrNotFound
	}
	return r, err
}

// FindByIdempotencyKey implements request.Store.
func (s *Store) FindByIdempotencyKey(ctx context.Context, agent, key string) (*request.Request, error) {
	r, err := scanRequest(s.db.QueryRowContext(ctx,
		`SELECT `+requestColumns+` FROM requests WHERE agent = ? AND idempotency_key = ?`, agent, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, request.ErrNotFound
	}
	return r, err
}

// ListRequests implements request.Store.
func (s *Store) ListRequests(ctx context.Context, f request.ListFilter) ([]request.Request, error) {
	var where []string
	var args []any
	if f.Status != "" {
		where, args = append(where, "status = ?"), append(args, string(f.Status))
	}
	if f.Agent != "" {
		where, args = append(where, "agent = ?"), append(args, f.Agent)
	}
	q := `SELECT ` + requestColumns + ` FROM requests`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC, id DESC LIMIT ?"
	args = append(args, clampLimit(f.Limit))
	return s.queryRequests(ctx, q, args...)
}

// ExpiredPending implements request.Store.
func (s *Store) ExpiredPending(ctx context.Context, now time.Time) ([]request.Request, error) {
	return s.queryRequests(ctx, `SELECT `+requestColumns+` FROM requests
		WHERE status = ? AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY created_at`,
		string(request.Pending), formatTime(now))
}

func (s *Store) queryRequests(ctx context.Context, q string, args ...any) ([]request.Request, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list requests: %w", err)
	}
	defer rows.Close()
	var out []request.Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// Transition implements request.Store.
func (s *Store) Transition(ctx context.Context, id string, from, to request.Status, u request.Update) error {
	if !request.CanTransition(from, to) {
		return fmt.Errorf("illegal transition %s -> %s", from, to)
	}
	if u.At.IsZero() {
		u.At = time.Now()
	}
	sets := []string{"status = ?"}
	args := []any{string(to)}
	switch to {
	case request.Approved, request.Denied, request.Expired:
		sets = append(sets, "decided_at = ?", "decided_by = ?", "decision_note = ?")
		args = append(args, formatTime(u.At), u.DecidedBy, u.DecisionNote)
	case request.Executed, request.Failed:
		errJSON, err := marshalError(u.Error)
		if err != nil {
			return err
		}
		sets = append(sets, "completed_at = ?", "result = ?", "error = ?")
		args = append(args, formatTime(u.At), nullBytes(u.Result), errJSON)
	}
	args = append(args, id, string(from))
	res, err := s.db.ExecContext(ctx, `UPDATE requests SET `+strings.Join(sets, ", ")+
		` WHERE id = ? AND status = ?`, args...)
	if err != nil {
		return fmt.Errorf("transition request: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.GetRequest(ctx, id); errors.Is(err, request.ErrNotFound) {
			return request.ErrNotFound
		}
		return request.ErrStateConflict
	}
	return nil
}

func clampLimit(n int) int {
	if n <= 0 {
		return 100
	}
	return min(n, 1000)
}

func formatTime(t time.Time) string { return t.UTC().Format(tsFormat) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(tsFormat, s)
	return t
}

func parseNullTime(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t := parseTime(s.String)
	return &t
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

func marshalError(e *core.Error) (any, error) {
	if e == nil {
		return nil, nil
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// Package audit defines the append-only audit trail (spec §17).
package audit

import (
	"context"
	"encoding/json"
	"time"
)

// Event types.
const (
	// EventRequest is written before anything executes, for every call.
	EventRequest = "request"
	// EventResult is written after a capability ran.
	EventResult = "result"
	// EventApproval records a human or automatic decision on a pending request.
	EventApproval = "approval"
	// EventRetention records that old records were archived and removed.
	EventRetention = "retention"
)

// Result values.
const (
	ResultStarted          = "started"
	ResultSuccess          = "success"
	ResultError            = "error"
	ResultDenied           = "denied"
	ResultInvalid          = "invalid"
	ResultApprovalRequired = "approval_required"
	ResultDuplicate        = "duplicate"
	ResultApproved         = "approved"
	ResultRejected         = "rejected"
	ResultExpired          = "expired"
	ResultPruned           = "pruned"
)

// Record is one audit log entry. Arguments are redacted before persistence.
type Record struct {
	ID             int64           `json:"id"`
	Time           time.Time       `json:"timestamp"`
	Event          string          `json:"event"`
	Agent          string          `json:"agent,omitempty"`
	Session        string          `json:"session,omitempty"`
	Capability     string          `json:"capability,omitempty"`
	Resource       string          `json:"resource,omitempty"`
	ArgumentsHash  string          `json:"arguments_hash,omitempty"`
	Arguments      json.RawMessage `json:"arguments,omitempty"`
	PolicyDecision string          `json:"policy_decision,omitempty"`
	PolicyRule     string          `json:"policy_rule,omitempty"`
	RequestID      string          `json:"request_id,omitempty"`
	Result         string          `json:"result"`
	ErrorCode      string          `json:"error_code,omitempty"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	DurationMS     int64           `json:"duration_ms,omitempty"`
	Actor          string          `json:"actor,omitempty"`
	// Note explains system records, e.g. what retention removed.
	Note string `json:"note,omitempty"`
}

// Filter selects audit records. With AfterID set, records are returned in
// ascending order starting after that ID; otherwise the newest Limit records
// are returned, oldest first.
type Filter struct {
	Agent      string
	Capability string
	RequestID  string
	AfterID    int64
	Limit      int
}

// Log persists audit records.
type Log interface {
	Append(ctx context.Context, r *Record) error
	List(ctx context.Context, f Filter) ([]Record, error)
}

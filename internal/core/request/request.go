// Package request models tracked capability requests: every mutating call and
// every call that needs human approval (spec §16).
package request

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/w512/SysRail/internal/core"
)

// Status is the lifecycle state of a request (spec §16.1).
type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Denied   Status = "denied"
	Expired  Status = "expired"
	Executed Status = "executed"
	Failed   Status = "failed"
)

// Terminal reports whether no further transitions are possible.
func (s Status) Terminal() bool {
	return s == Denied || s == Expired || s == Executed || s == Failed
}

var transitions = map[Status][]Status{
	Pending:  {Approved, Denied, Expired},
	Approved: {Executed, Failed},
}

// CanTransition reports whether from -> to is a legal transition.
func CanTransition(from, to Status) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Request is a tracked capability call.
type Request struct {
	ID             string          `json:"request_id"`
	Agent          string          `json:"agent"`
	Session        string          `json:"session,omitempty"`
	Capability     string          `json:"capability"`
	Resource       string          `json:"resource,omitempty"`
	Args           json.RawMessage `json:"arguments"`
	ArgsHash       string          `json:"arguments_hash"`
	Reason         string          `json:"reason,omitempty"`
	Risk           core.Risk       `json:"risk"`
	Status         Status          `json:"status"`
	PolicyRule     string          `json:"policy_rule,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
	DecidedAt      *time.Time      `json:"decided_at,omitempty"`
	DecidedBy      string          `json:"decided_by,omitempty"`
	DecisionNote   string          `json:"decision_note,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	Error          *core.Error     `json:"error,omitempty"`
}

// Update carries the fields set by a transition.
type Update struct {
	At           time.Time
	DecidedBy    string
	DecisionNote string
	Result       json.RawMessage
	Error        *core.Error
}

// ListFilter selects requests, newest first.
type ListFilter struct {
	Status Status
	Agent  string
	Limit  int
}

var (
	// ErrNotFound means no request has the given ID.
	ErrNotFound = errors.New("request not found")
	// ErrStateConflict means the request was not in the expected state.
	ErrStateConflict = errors.New("request state changed")
	// ErrDuplicateKey means the agent already used the idempotency key.
	ErrDuplicateKey = errors.New("idempotency key already used")
)

// Store persists requests.
type Store interface {
	CreateRequest(ctx context.Context, r *Request) error
	GetRequest(ctx context.Context, id string) (*Request, error)
	FindByIdempotencyKey(ctx context.Context, agent, key string) (*Request, error)
	ListRequests(ctx context.Context, f ListFilter) ([]Request, error)
	// Transition atomically moves a request from one status to another and
	// applies u. It returns ErrStateConflict if the current status is not from.
	Transition(ctx context.Context, id string, from, to Status, u Update) error
	// ExpiredPending returns pending requests whose expiry is before now.
	ExpiredPending(ctx context.Context, now time.Time) ([]Request, error)
	// CountPending counts an agent's pending requests that have not expired
	// at now.
	CountPending(ctx context.Context, agent string, now time.Time) (int, error)
}

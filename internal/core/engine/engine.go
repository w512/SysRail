// Package engine implements the request pipeline shared by every transport:
// validate -> policy -> (deny | approval request | execute) with an audit
// record written before anything runs.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/policy"
	"github.com/w512/SysRail/internal/core/redact"
	"github.com/w512/SysRail/internal/core/request"
)

// Outcome statuses.
const (
	StatusSuccess          = "success"
	StatusApprovalRequired = "approval_required"
	StatusInProgress       = "in_progress"
)

const (
	maxReasonLen = 500
	maxKeyLen    = 128
)

// Store is the persistence the engine needs.
type Store interface {
	audit.Log
	request.Store
}

// Options configures an Engine.
type Options struct {
	Registry    *core.Registry
	Policy      *policy.Policy
	Store       Store
	ApprovalTTL time.Duration
	Logger      *slog.Logger
	Now         func() time.Time
}

// Engine executes capability calls.
type Engine struct {
	reg    *core.Registry
	policy atomic.Pointer[policy.Policy]
	store  Store
	ttl    time.Duration
	log    *slog.Logger
	now    func() time.Time
}

// New builds an engine.
func New(opts Options) (*Engine, error) {
	if opts.Registry == nil || opts.Policy == nil || opts.Store == nil {
		return nil, errors.New("engine: registry, policy and store are required")
	}
	e := &Engine{reg: opts.Registry, store: opts.Store, ttl: opts.ApprovalTTL, log: opts.Logger, now: opts.Now}
	if e.ttl <= 0 {
		e.ttl = 15 * time.Minute
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	if e.now == nil {
		e.now = time.Now
	}
	e.policy.Store(opts.Policy)
	return e, nil
}

// Registry returns the capability registry.
func (e *Engine) Registry() *core.Registry { return e.reg }

// Policy returns the active policy.
func (e *Engine) Policy() *policy.Policy { return e.policy.Load() }

// SetPolicy atomically replaces the active policy.
func (e *Engine) SetPolicy(p *policy.Policy) { e.policy.Store(p) }

// Call is a request to run a capability on behalf of an agent.
type Call struct {
	Agent          string
	Session        string
	Capability     string
	Args           json.RawMessage
	Reason         string
	IdempotencyKey string
}

// Outcome is the successful (non-error) result of a call.
type Outcome struct {
	Status    string          `json:"status"`
	RequestID string          `json:"request_id,omitempty"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
}

// Execute runs the full pipeline for one call. Errors are always *core.Error.
func (e *Engine) Execute(ctx context.Context, call Call) (*Outcome, error) {
	ctx = core.WithCaller(ctx, core.Caller{Agent: call.Agent, Session: call.Session})
	rec := audit.Record{
		Event: audit.EventRequest, Agent: call.Agent, Session: call.Session, Capability: call.Capability,
	}
	reject := func(result string, err *core.Error) (*Outcome, error) {
		rec.Result = result
		rec.ErrorCode, rec.ErrorMessage = string(err.Code), err.Message
		if aerr := e.appendAudit(ctx, &rec); aerr != nil {
			return nil, aerr
		}
		return nil, err
	}

	c, ok := e.reg.ByID(call.Capability)
	if !ok {
		return reject(audit.ResultInvalid, core.Errorf(core.CodeResourceNotFound, "unknown capability %q", call.Capability))
	}
	if err := checkMeta(call); err != nil {
		return reject(audit.ResultInvalid, err)
	}
	inv, err := c.Bind(call.Args)
	if err != nil {
		cerr := core.AsError(err)
		result := audit.ResultInvalid
		if cerr.Code == core.CodePermissionDenied {
			// Providers refuse some resources outright (e.g. protected units).
			result = audit.ResultDenied
		}
		return reject(result, cerr)
	}
	hash := argsHash(c.ID, inv.Args)
	rec.Resource, rec.ArgumentsHash, rec.Arguments = inv.Resource, hash, redact.JSON(inv.Args)

	decision := policy.Decision{Action: policy.Allow, Rule: "built-in"}
	if !c.AlwaysAllowed {
		decision = e.Policy().Decide(call.Agent, c.Permission, c.ResourceKind, inv.Resource)
	}
	rec.PolicyDecision, rec.PolicyRule = string(decision.Action), decision.Rule

	if decision.Action == policy.Deny {
		msg := fmt.Sprintf("agent %q is not permitted to use %s", call.Agent, c.Permission)
		if inv.Resource != "" {
			msg += " on " + inv.Resource
		}
		return reject(audit.ResultDenied, core.Errorf(core.CodePermissionDenied, "%s", msg))
	}

	tracked := c.Mutating || decision.Action == policy.Ask
	if tracked && call.IdempotencyKey != "" {
		existing, err := e.store.FindByIdempotencyKey(ctx, call.Agent, call.IdempotencyKey)
		switch {
		case err == nil:
			if existing.Capability != c.ID || existing.ArgsHash != hash {
				return reject(audit.ResultInvalid, core.Errorf(core.CodeConflict,
					"idempotency key was already used for a different request"))
			}
			rec.Result, rec.RequestID = audit.ResultDuplicate, existing.ID
			if aerr := e.appendAudit(ctx, &rec); aerr != nil {
				return nil, aerr
			}
			return outcomeFor(existing)
		case !errors.Is(err, request.ErrNotFound):
			return nil, e.storeError("look up idempotency key", err)
		}
	}

	if !tracked {
		rec.Result = audit.ResultStarted
		if aerr := e.appendAudit(ctx, &rec); aerr != nil {
			return nil, aerr
		}
		result, start, rerr := e.run(ctx, c, inv)
		e.auditResult(ctx, rec, start, rerr)
		if rerr != nil {
			return nil, rerr
		}
		return &Outcome{Status: StatusSuccess, Result: result}, nil
	}

	now := e.now()
	req := &request.Request{
		ID: core.NewID("req"), Agent: call.Agent, Session: call.Session, Capability: c.ID,
		Resource: inv.Resource, Args: inv.Args, ArgsHash: hash, Reason: call.Reason, Risk: c.Risk,
		PolicyRule: decision.Rule, IdempotencyKey: call.IdempotencyKey, CreatedAt: now,
	}
	rec.RequestID = req.ID
	if decision.Action == policy.Ask {
		exp := now.Add(e.ttl)
		req.Status, req.ExpiresAt = request.Pending, &exp
		rec.Result = audit.ResultApprovalRequired
	} else {
		req.Status, req.DecidedAt, req.DecidedBy = request.Approved, &now, "policy"
		rec.Result = audit.ResultStarted
	}
	if aerr := e.appendAudit(ctx, &rec); aerr != nil {
		return nil, aerr
	}
	if err := e.store.CreateRequest(ctx, req); err != nil {
		if errors.Is(err, request.ErrDuplicateKey) {
			if existing, ferr := e.store.FindByIdempotencyKey(ctx, call.Agent, call.IdempotencyKey); ferr == nil &&
				existing.ArgsHash == hash && existing.Capability == c.ID {
				return outcomeFor(existing)
			}
			return nil, core.Errorf(core.CodeConflict, "idempotency key was already used for a different request")
		}
		return nil, e.storeError("create request", err)
	}
	if req.Status == request.Pending {
		return &Outcome{Status: StatusApprovalRequired, RequestID: req.ID, ExpiresAt: req.ExpiresAt}, nil
	}
	return e.complete(ctx, c, inv, req, rec)
}

// complete runs an approved request and records the outcome.
func (e *Engine) complete(ctx context.Context, c *core.Capability, inv *core.Invocation, req *request.Request, rec audit.Record) (*Outcome, error) {
	result, start, rerr := e.run(ctx, c, inv)
	to, upd := request.Executed, request.Update{At: e.now(), Result: result}
	if rerr != nil {
		to, upd = request.Failed, request.Update{At: e.now(), Error: rerr}
	}
	if err := e.store.Transition(context.WithoutCancel(ctx), req.ID, request.Approved, to, upd); err != nil {
		e.log.Error("record request completion", "request_id", req.ID, "error", err)
	}
	e.auditResult(ctx, rec, start, rerr)
	if rerr != nil {
		return nil, rerr
	}
	return &Outcome{Status: StatusSuccess, RequestID: req.ID, Result: result}, nil
}

// run executes an invocation with the capability timeout and redacts the
// result. Mutations are detached from caller cancellation so a disconnecting
// client cannot abort them halfway.
func (e *Engine) run(ctx context.Context, c *core.Capability, inv *core.Invocation) (json.RawMessage, time.Time, *core.Error) {
	if c.Mutating {
		ctx = context.WithoutCancel(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	start := e.now()
	out, err := inv.Run(ctx)
	if err != nil {
		cerr := core.AsError(err)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && cerr.Code == core.CodeExecutionFailed {
			cerr = core.Errorf(core.CodeTimeout, "%s did not finish within %s", c.ID, c.Timeout)
		}
		clean := *cerr
		clean.Message = redact.String(clean.Message)
		return nil, start, &clean
	}
	raw, err := redact.Marshal(out)
	if err != nil {
		return nil, start, core.Errorf(core.CodeExecutionFailed, "encode result: %v", err)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		raw, _ = json.Marshal(map[string]json.RawMessage{"value": raw})
	}
	return raw, start, nil
}

func (e *Engine) auditResult(ctx context.Context, rec audit.Record, start time.Time, rerr *core.Error) {
	rec.ID = 0
	rec.Event = audit.EventResult
	rec.Time = time.Time{}
	rec.Arguments = nil
	rec.DurationMS = e.now().Sub(start).Milliseconds()
	rec.Result = audit.ResultSuccess
	if rerr != nil {
		rec.Result, rec.ErrorCode, rec.ErrorMessage = audit.ResultError, string(rerr.Code), rerr.Message
	}
	if err := e.store.Append(context.WithoutCancel(ctx), &rec); err != nil {
		e.log.Error("audit write failed after execution", "capability", rec.Capability,
			"request_id", rec.RequestID, "error", err)
	}
}

// appendAudit writes a record that must succeed before anything executes.
func (e *Engine) appendAudit(ctx context.Context, rec *audit.Record) *core.Error {
	rec.Time = e.now()
	if err := e.store.Append(context.WithoutCancel(ctx), rec); err != nil {
		e.log.Error("audit write failed; refusing request", "capability", rec.Capability, "error", err)
		return &core.Error{Code: core.CodeExecutionFailed, Message: "audit log unavailable; request refused", Retryable: true}
	}
	return nil
}

func (e *Engine) storeError(op string, err error) *core.Error {
	e.log.Error("request store failure", "op", op, "error", err)
	return &core.Error{Code: core.CodeExecutionFailed, Message: "request store unavailable", Retryable: true}
}

func outcomeFor(r *request.Request) (*Outcome, error) {
	switch r.Status {
	case request.Pending:
		return &Outcome{Status: StatusApprovalRequired, RequestID: r.ID, ExpiresAt: r.ExpiresAt}, nil
	case request.Approved:
		return &Outcome{Status: StatusInProgress, RequestID: r.ID}, nil
	case request.Executed:
		return &Outcome{Status: StatusSuccess, RequestID: r.ID, Result: r.Result}, nil
	case request.Failed:
		if r.Error != nil {
			return nil, r.Error
		}
		return nil, core.Errorf(core.CodeExecutionFailed, "request %s failed", r.ID)
	case request.Denied:
		return nil, core.Errorf(core.CodePermissionDenied, "request %s was denied", r.ID).WithDetail("request_id", r.ID)
	}
	return nil, core.Errorf(core.CodeConflict, "request %s is %s", r.ID, r.Status).WithDetail("request_id", r.ID)
}

func checkMeta(call Call) *core.Error {
	if utf8.RuneCountInString(call.Reason) > maxReasonLen {
		return core.Errorf(core.CodeInvalidArgument, "reason must be at most %d characters", maxReasonLen)
	}
	if len(call.IdempotencyKey) > maxKeyLen {
		return core.Errorf(core.CodeInvalidArgument, "idempotency_key must be at most %d bytes", maxKeyLen)
	}
	for _, r := range call.IdempotencyKey {
		if r < 0x21 || r > 0x7e {
			return core.Errorf(core.CodeInvalidArgument, "idempotency_key must be printable ASCII without spaces")
		}
	}
	return nil
}

func argsHash(capability string, args json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(capability))
	h.Write([]byte{0})
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/policy"
	"github.com/w512/SysRail/internal/core/request"
)

// Approve records a human approval for a pending request and executes it
// with the stored, re-validated arguments. It returns the final request.
func (e *Engine) Approve(ctx context.Context, id, actor, note string) (*request.Request, error) {
	req, err := e.pending(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := e.store.Transition(ctx, id, request.Pending, request.Approved,
		request.Update{At: e.now(), DecidedBy: actor, DecisionNote: note}); err != nil {
		return nil, e.transitionError(id, err)
	}
	rec := audit.Record{
		Event: audit.EventApproval, Agent: req.Agent, Session: req.Session, Capability: req.Capability,
		Resource: req.Resource, ArgumentsHash: req.ArgsHash, RequestID: id, Result: audit.ResultApproved,
		Actor: actor,
	}
	if aerr := e.appendAudit(ctx, &rec); aerr != nil {
		e.fail(ctx, id, aerr)
		return nil, aerr
	}

	ctx = core.WithCaller(ctx, core.Caller{Agent: req.Agent, Session: req.Session})
	c, inv, cerr := e.revalidate(req)
	if cerr != nil {
		e.fail(ctx, id, cerr)
		e.auditResult(ctx, rec, e.now(), cerr)
		return e.store.GetRequest(ctx, id)
	}
	if _, err := e.complete(ctx, c, inv, req, rec); err != nil {
		e.log.Info("approved request failed", "request_id", id, "error", err)
	}
	return e.store.GetRequest(ctx, id)
}

// revalidate re-binds stored arguments and re-checks policy before running an
// approved request. The arguments must hash to what the agent originally sent.
func (e *Engine) revalidate(req *request.Request) (*core.Capability, *core.Invocation, *core.Error) {
	c, ok := e.reg.ByID(req.Capability)
	if !ok {
		return nil, nil, core.Errorf(core.CodeProviderUnavailable, "capability %s is no longer available", req.Capability)
	}
	inv, err := c.Bind(req.Args)
	if err != nil {
		return nil, nil, core.AsError(err)
	}
	if argsHash(c.ID, inv.Args) != req.ArgsHash || inv.Resource != req.Resource {
		return nil, nil, core.Errorf(core.CodeConflict, "stored arguments do not match the approved request")
	}
	if !c.AlwaysAllowed {
		if d := e.Policy().Decide(req.Agent, c.Permission, c.ResourceKind, inv.Resource); d.Action == policy.Deny {
			return nil, nil, core.Errorf(core.CodePermissionDenied, "policy no longer permits this request (%s)", d.Rule)
		}
	}
	return c, inv, nil
}

func (e *Engine) fail(ctx context.Context, id string, cerr *core.Error) {
	if err := e.store.Transition(context.WithoutCancel(ctx), id, request.Approved, request.Failed,
		request.Update{At: e.now(), Error: cerr}); err != nil {
		e.log.Error("mark request failed", "request_id", id, "error", err)
	}
}

// Deny rejects a pending request.
func (e *Engine) Deny(ctx context.Context, id, actor, note string) (*request.Request, error) {
	req, err := e.pending(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := e.store.Transition(ctx, id, request.Pending, request.Denied,
		request.Update{At: e.now(), DecidedBy: actor, DecisionNote: note}); err != nil {
		return nil, e.transitionError(id, err)
	}
	rec := audit.Record{
		Event: audit.EventApproval, Agent: req.Agent, Session: req.Session, Capability: req.Capability,
		Resource: req.Resource, ArgumentsHash: req.ArgsHash, RequestID: id, Result: audit.ResultRejected,
		Actor: actor,
	}
	if aerr := e.appendAudit(ctx, &rec); aerr != nil {
		e.log.Error("audit write failed for denial", "request_id", id)
	}
	return e.store.GetRequest(ctx, id)
}

// pending loads a request that must still be awaiting a decision, expiring it
// first if its deadline has passed.
func (e *Engine) pending(ctx context.Context, id string) (*request.Request, error) {
	req, err := e.store.GetRequest(ctx, id)
	if errors.Is(err, request.ErrNotFound) {
		return nil, core.Errorf(core.CodeResourceNotFound, "request %s not found", id)
	}
	if err != nil {
		return nil, e.storeError("get request", err)
	}
	if req.Status == request.Pending && e.expired(req) {
		e.expire(ctx, req)
		return nil, core.Errorf(core.CodeConflict, "request %s has expired", id)
	}
	if req.Status != request.Pending {
		return nil, core.Errorf(core.CodeConflict, "request %s is %s", id, req.Status)
	}
	return req, nil
}

func (e *Engine) transitionError(id string, err error) error {
	if errors.Is(err, request.ErrStateConflict) {
		return core.Errorf(core.CodeConflict, "request %s was decided concurrently", id)
	}
	if errors.Is(err, request.ErrNotFound) {
		return core.Errorf(core.CodeResourceNotFound, "request %s not found", id)
	}
	return e.storeError("transition request", err)
}

func (e *Engine) expired(r *request.Request) bool {
	return r.ExpiresAt != nil && !e.now().Before(*r.ExpiresAt)
}

func (e *Engine) expire(ctx context.Context, r *request.Request) {
	err := e.store.Transition(context.WithoutCancel(ctx), r.ID, request.Pending, request.Expired,
		request.Update{At: e.now(), DecidedBy: "system"})
	if err != nil {
		if !errors.Is(err, request.ErrStateConflict) {
			e.log.Error("expire request", "request_id", r.ID, "error", err)
		}
		return
	}
	rec := audit.Record{
		Event: audit.EventApproval, Agent: r.Agent, Session: r.Session, Capability: r.Capability,
		Resource: r.Resource, ArgumentsHash: r.ArgsHash, RequestID: r.ID, Result: audit.ResultExpired,
		Actor: "system",
	}
	if aerr := e.appendAudit(ctx, &rec); aerr != nil {
		e.log.Error("audit write failed for expiry", "request_id", r.ID)
	}
}

// ExpireStale expires every pending request past its deadline.
func (e *Engine) ExpireStale(ctx context.Context) (int, error) {
	stale, err := e.store.ExpiredPending(ctx, e.now())
	if err != nil {
		return 0, err
	}
	for i := range stale {
		e.expire(ctx, &stale[i])
	}
	return len(stale), nil
}

// GetRequest returns a request by ID (admin view).
func (e *Engine) GetRequest(ctx context.Context, id string) (*request.Request, error) {
	req, err := e.store.GetRequest(ctx, id)
	if errors.Is(err, request.ErrNotFound) {
		return nil, core.Errorf(core.CodeResourceNotFound, "request %s not found", id)
	}
	if err != nil {
		return nil, e.storeError("get request", err)
	}
	if req.Status == request.Pending && e.expired(req) {
		e.expire(ctx, req)
		return e.store.GetRequest(ctx, id)
	}
	return req, nil
}

// ListRequests lists requests (admin view).
func (e *Engine) ListRequests(ctx context.Context, f request.ListFilter) ([]request.Request, error) {
	if _, err := e.ExpireStale(ctx); err != nil {
		e.log.Error("expire stale requests", "error", err)
	}
	return e.store.ListRequests(ctx, f)
}

// Audit lists audit records (admin view).
func (e *Engine) Audit(ctx context.Context, f audit.Filter) ([]audit.Record, error) {
	return e.store.List(ctx, f)
}

// RequestView is what an agent may see about its own request.
type RequestView struct {
	RequestID    string          `json:"request_id"`
	Status       request.Status  `json:"status"`
	Capability   string          `json:"capability"`
	Resource     string          `json:"resource,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	ExpiresAt    *time.Time      `json:"expires_at,omitempty"`
	DecidedAt    *time.Time      `json:"decided_at,omitempty"`
	DecisionNote string          `json:"decision_note,omitempty"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	Error        *core.Error     `json:"error,omitempty"`
}

type requestStatusArgs struct {
	RequestID   string `json:"request_id" jsonschema:"ID returned by a call that required approval"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"Wait up to this many seconds (0-30) for a decision or result"`
}

const maxWait = 30 * time.Second

// Builtins returns capabilities implemented by the core itself.
func Builtins(store request.Store) []core.Capability {
	schema := core.SchemaFor[requestStatusArgs](func(p map[string]*jsonschema.Schema) {
		p["wait_seconds"].Minimum = core.Ptr(0.0)
		p["wait_seconds"].Maximum = core.Ptr(maxWait.Seconds())
		p["request_id"].MaxLength = core.Ptr(64)
	})
	return []core.Capability{
		core.Define(core.Capability{
			ID: "request.status", Tool: "request_get_status",
			Description: "Get the status and, once finished, the result of your own request that " +
				"required human approval. Optionally waits for a decision.",
			Risk: core.RiskRead, AlwaysAllowed: true, Timeout: maxWait + 5*time.Second,
			InputSchema: schema,
		}, nil, func(ctx context.Context, in requestStatusArgs) (any, error) {
			return requestStatus(ctx, store, in)
		}),
	}
}

func requestStatus(ctx context.Context, store request.Store, in requestStatusArgs) (any, error) {
	caller, ok := core.CallerFrom(ctx)
	if !ok {
		return nil, core.Errorf(core.CodeAuthenticationFailed, "no caller identity")
	}
	deadline := time.Now().Add(time.Duration(in.WaitSeconds) * time.Second)
	for {
		req, err := store.GetRequest(ctx, in.RequestID)
		if errors.Is(err, request.ErrNotFound) || (err == nil && req.Agent != caller.Agent) {
			return nil, core.Errorf(core.CodeResourceNotFound, "request %s not found", in.RequestID)
		}
		if err != nil {
			return nil, err
		}
		if req.Status == request.Pending && req.ExpiresAt != nil && !time.Now().Before(*req.ExpiresAt) {
			req.Status = request.Expired
		}
		if req.Status.Terminal() || !time.Now().Before(deadline) {
			return RequestView{
				RequestID: req.ID, Status: req.Status, Capability: req.Capability, Resource: req.Resource,
				CreatedAt: req.CreatedAt, ExpiresAt: req.ExpiresAt, DecidedAt: req.DecidedAt,
				DecisionNote: req.DecisionNote, CompletedAt: req.CompletedAt, Result: req.Result, Error: req.Error,
			}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

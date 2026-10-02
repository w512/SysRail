package engine

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
)

// Limits bound what one agent can do. Zero values disable a limit.
type Limits struct {
	// CallsPerMinute is the sustained call rate across all capabilities.
	CallsPerMinute int
	// Burst is how many calls may be made back to back.
	Burst int
	// MaxPending caps requests waiting for approval at the same time.
	MaxPending int
}

// rejectionAuditInterval is how often a rate-limited agent gets an individual
// audit record; rejections in between are counted and summarized, so an
// agent flooding the API cannot flood the audit log as well.
const rejectionAuditInterval = 10 * time.Second

type agentLimiter struct {
	limits     Limits
	bucket     *rate.Limiter // nil when the call rate is unlimited
	lastAudit  time.Time     // last individually audited rejection
	suppressed int           // rejections since lastAudit, not yet recorded
	first      time.Time     // first suppressed rejection
	session    string
}

type limiters struct {
	mu     sync.Mutex
	agents map[string]*agentLimiter
	pendMu sync.Mutex // serializes the pending-request check and creation
}

func (e *Engine) limiter(agent string) *agentLimiter {
	e.limits.mu.Lock()
	defer e.limits.mu.Unlock()
	if e.limits.agents == nil {
		e.limits.agents = map[string]*agentLimiter{}
	}
	if al, ok := e.limits.agents[agent]; ok {
		return al
	}
	al := &agentLimiter{}
	if e.limitsFor != nil {
		al.limits = e.limitsFor(agent)
	}
	if l := al.limits; l.CallsPerMinute > 0 {
		burst := max(l.Burst, 1)
		al.bucket = rate.NewLimiter(rate.Limit(float64(l.CallsPerMinute)/60), burst)
	}
	e.limits.agents[agent] = al
	return al
}

// checkRate admits or rejects a call under the agent's rate limit.
func (e *Engine) checkRate(ctx context.Context, call Call) error {
	al := e.limiter(call.Agent)
	if al.bucket == nil {
		return nil
	}
	now := e.now()
	r := al.bucket.ReserveN(now, 1)
	delay := r.DelayFrom(now)
	if delay <= 0 {
		e.flushRateSummary(ctx, call.Agent, al, false)
		return nil
	}
	r.CancelAt(now)
	retry := int(math.Ceil(delay.Seconds()))
	cerr := core.Errorf(core.CodeRateLimited,
		"agent %q exceeded %d calls per minute; retry in %ds", call.Agent, al.limits.CallsPerMinute, retry).
		WithDetail("retry_after_seconds", retry)

	e.limits.mu.Lock()
	audited := al.lastAudit.IsZero() || now.Sub(al.lastAudit) >= rejectionAuditInterval
	var note string
	if audited {
		if al.suppressed > 0 {
			note = fmt.Sprintf("%d more calls were rejected by the rate limit since %s and not recorded individually",
				al.suppressed, al.first.UTC().Format(time.RFC3339))
		}
		al.lastAudit, al.suppressed = now, 0
	} else {
		if al.suppressed == 0 {
			al.first = now
		}
		al.suppressed++
		al.session = call.Session
	}
	e.limits.mu.Unlock()

	if audited {
		rec := &audit.Record{
			Event: audit.EventRequest, Agent: call.Agent, Session: call.Session, Capability: call.Capability,
			Result: audit.ResultRateLimited, ErrorCode: string(cerr.Code), ErrorMessage: cerr.Message, Note: note,
			Time: now,
		}
		if err := e.store.Append(context.WithoutCancel(ctx), rec); err != nil {
			e.log.Error("audit write failed for rate-limited call", "agent", call.Agent, "error", err)
		}
	}
	return cerr
}

// flushRateSummary records rejections that were only counted. Unless force
// is set, it waits until the audit interval has passed so a recovering agent
// does not produce one summary per call.
func (e *Engine) flushRateSummary(ctx context.Context, agent string, al *agentLimiter, force bool) {
	now := e.now()
	e.limits.mu.Lock()
	if al.suppressed == 0 || (!force && now.Sub(al.lastAudit) < rejectionAuditInterval) {
		e.limits.mu.Unlock()
		return
	}
	n, first, session := al.suppressed, al.first, al.session
	al.suppressed, al.lastAudit = 0, now
	e.limits.mu.Unlock()
	rec := &audit.Record{
		Event: audit.EventRateLimit, Agent: agent, Session: session, Result: audit.ResultRateLimited,
		ErrorCode: string(core.CodeRateLimited), Time: now,
		Note: fmt.Sprintf("%d calls were rejected by the rate limit between %s and %s and not recorded individually",
			n, first.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)),
	}
	if err := e.store.Append(context.WithoutCancel(ctx), rec); err != nil {
		e.log.Error("audit write failed for rate limit summary", "agent", agent, "error", err)
	}
}

// FlushRateLimits writes pending rate-limit summaries. The daemon calls it
// periodically and at shutdown so counted rejections are never lost.
func (e *Engine) FlushRateLimits(ctx context.Context, force bool) {
	e.limits.mu.Lock()
	agents := make(map[string]*agentLimiter, len(e.limits.agents))
	for name, al := range e.limits.agents {
		agents[name] = al
	}
	e.limits.mu.Unlock()
	for name, al := range agents {
		e.flushRateSummary(ctx, name, al, force)
	}
}

// checkPending enforces MaxPending. The caller must hold e.limits.pendMu
// until the new request is stored.
func (e *Engine) checkPending(ctx context.Context, agent string) *core.Error {
	limit := e.limiter(agent).limits.MaxPending
	if limit <= 0 {
		return nil
	}
	n, err := e.store.CountPending(ctx, agent, e.now())
	if err != nil {
		return e.storeError("count pending requests", err)
	}
	if n >= limit {
		return core.Errorf(core.CodeRateLimited,
			"agent %q already has %d requests waiting for approval (limit %d); wait for decisions before asking for more",
			agent, n, limit)
	}
	return nil
}

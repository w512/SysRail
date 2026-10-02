// Package httpapi serves the SysRail HTTP API (spec §7.2). The agent API
// requires a bearer token; the admin API is served only on the admin socket
// or to holders of the admin token. Both are thin layers over the engine.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/w512/SysRail/internal/auth"
	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/core/engine"
	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/core/request"
	"github.com/w512/SysRail/internal/version"
)

const (
	maxBody = 1 << 20
	// SessionHeader carries an optional client session identifier.
	SessionHeader = "X-SysRail-Session"
	// ActorHeader carries the approver's claimed identity (informational).
	ActorHeader = "X-SysRail-Actor"
)

var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// CapabilityInfo describes a capability to API clients.
type CapabilityInfo struct {
	ID           string             `json:"id"`
	Tool         string             `json:"tool"`
	Description  string             `json:"description"`
	Risk         core.Risk          `json:"risk"`
	Mutating     bool               `json:"mutating"`
	Permission   string             `json:"permission,omitempty"`
	ResourceKind string             `json:"resource_kind,omitempty"`
	Impact       string             `json:"impact,omitempty"`
	InputSchema  *jsonschema.Schema `json:"input_schema"`
}

// ExecuteRequest is the body of POST /v1/execute.
type ExecuteRequest struct {
	Capability     string          `json:"capability"`
	Arguments      json.RawMessage `json:"arguments,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
}

// DecisionRequest is the body of approve/deny calls.
type DecisionRequest struct {
	Note string `json:"note,omitempty"`
}

// ErrorBody wraps errors in responses.
type ErrorBody struct {
	Error *core.Error `json:"error"`
}

type agentKey struct{}

// NewAgentHandler serves the agent API.
func NewAgentHandler(eng *engine.Engine, authn *auth.Authenticator, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", notFound)
	mux.HandleFunc("GET /v1/health", health)
	requireAgent := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			agent, ok := authn.Agent(bearer(r))
			if !ok {
				writeError(w, core.Errorf(core.CodeAuthenticationFailed, "missing or invalid bearer token"))
				return
			}
			h(w, r.WithContext(context.WithValue(r.Context(), agentKey{}, agent)))
		}
	}
	mux.HandleFunc("GET /v1/capabilities", requireAgent(func(w http.ResponseWriter, r *http.Request) {
		agent := r.Context().Value(agentKey{}).(string)
		p := eng.Policy()
		var out []CapabilityInfo
		for _, c := range eng.Registry().All() {
			if c.AlwaysAllowed || p.Reachable(agent, c.Permission) {
				out = append(out, info(c))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"agent": agent, "capabilities": out})
	}))
	mux.HandleFunc("POST /v1/execute", requireAgent(func(w http.ResponseWriter, r *http.Request) {
		var body ExecuteRequest
		if err := decode(w, r, &body); err != nil {
			writeError(w, err)
			return
		}
		session, err := session(r)
		if err != nil {
			writeError(w, err)
			return
		}
		out, xerr := eng.Execute(r.Context(), engine.Call{
			Agent: r.Context().Value(agentKey{}).(string), Session: session, Capability: body.Capability,
			Args: body.Arguments, Reason: body.Reason, IdempotencyKey: body.IdempotencyKey,
		})
		writeOutcome(w, out, xerr)
	}))
	mux.HandleFunc("GET /v1/events", requireAgent(func(w http.ResponseWriter, r *http.Request) {
		agent := r.Context().Value(agentKey{}).(string)
		serveEvents(eng.Events(), agentEventFilter(eng, agent))(w, r)
	}))
	mux.HandleFunc("GET /v1/requests/{id}", requireAgent(func(w http.ResponseWriter, r *http.Request) {
		session, err := session(r)
		if err != nil {
			writeError(w, err)
			return
		}
		wait := 0
		if v := r.URL.Query().Get("wait"); v != "" {
			n, perr := strconv.Atoi(v)
			if perr != nil {
				writeError(w, core.Errorf(core.CodeInvalidArgument, "wait must be an integer"))
				return
			}
			wait = n
		}
		args, _ := json.Marshal(map[string]any{"request_id": r.PathValue("id"), "wait_seconds": wait})
		out, xerr := eng.Execute(r.Context(), engine.Call{
			Agent: r.Context().Value(agentKey{}).(string), Session: session,
			Capability: "request.status", Args: args,
		})
		if xerr != nil {
			writeError(w, core.AsError(xerr))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(out.Result)
	}))
	return logRequests(log, "agent", mux)
}

// ActorFunc derives the approver identity for audit records.
type ActorFunc func(r *http.Request) string

// NewAdminHandler serves the admin API. It performs no authentication: it
// must only be reachable through the admin socket or WithAdminToken.
func NewAdminHandler(eng *engine.Engine, actor ActorFunc, log *slog.Logger) http.Handler {
	if actor == nil {
		actor = func(r *http.Request) string { return claimedActor(r, "admin") }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", notFound)
	mux.HandleFunc("GET /v1/health", health)
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		var out []CapabilityInfo
		for _, c := range eng.Registry().All() {
			out = append(out, info(c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"capabilities": out})
	})
	mux.HandleFunc("GET /v1/requests", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, err := intParam(q.Get("limit"))
		if err != nil {
			writeError(w, err)
			return
		}
		reqs, lerr := eng.ListRequests(r.Context(), request.ListFilter{
			Status: request.Status(q.Get("status")), Agent: q.Get("agent"), Limit: limit,
		})
		if lerr != nil {
			writeError(w, core.AsError(lerr))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": nonNil(reqs)})
	})
	mux.HandleFunc("GET /v1/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		req, err := eng.GetRequest(r.Context(), r.PathValue("id"))
		if err != nil {
			writeError(w, core.AsError(err))
			return
		}
		writeJSON(w, http.StatusOK, req)
	})
	decide := func(fn func(context.Context, string, string, string) (*request.Request, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var body DecisionRequest
			if err := decode(w, r, &body); err != nil {
				writeError(w, err)
				return
			}
			if len(body.Note) > 500 {
				writeError(w, core.Errorf(core.CodeInvalidArgument, "note must be at most 500 bytes"))
				return
			}
			req, err := fn(r.Context(), r.PathValue("id"), actor(r), body.Note)
			if err != nil {
				writeError(w, core.AsError(err))
				return
			}
			writeJSON(w, http.StatusOK, req)
		}
	}
	mux.HandleFunc("GET /v1/events", serveEvents(eng.Events(), func(events.Event) bool { return true }))
	mux.HandleFunc("POST /v1/requests/{id}/approve", decide(eng.Approve))
	mux.HandleFunc("POST /v1/requests/{id}/deny", decide(eng.Deny))
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, err := intParam(q.Get("limit"))
		if err != nil {
			writeError(w, err)
			return
		}
		after, err := intParam(q.Get("after_id"))
		if err != nil {
			writeError(w, err)
			return
		}
		recs, lerr := eng.Audit(r.Context(), audit.Filter{
			Agent: q.Get("agent"), Capability: q.Get("capability"), RequestID: q.Get("request_id"),
			AfterID: int64(after), Limit: limit,
		})
		if lerr != nil {
			writeError(w, core.AsError(lerr))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"records": nonNil(recs)})
	})
	return logRequests(log, "admin", mux)
}

// WithAdminToken routes requests bearing the admin token (by SHA-256 hash) to
// admin and everything else to agent. Used on the TCP listener.
func WithAdminToken(agent, admin http.Handler, adminHash string) http.Handler {
	want, _ := hex.DecodeString(adminHash)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok := bearer(r); tok != "" && len(want) == sha256.Size {
			sum := sha256.Sum256([]byte(tok))
			if subtle.ConstantTimeCompare(sum[:], want) == 1 {
				admin.ServeHTTP(w, r)
				return
			}
		}
		agent.ServeHTTP(w, r)
	})
}

func info(c *core.Capability) CapabilityInfo {
	return CapabilityInfo{
		ID: c.ID, Tool: c.Tool, Description: c.Description, Risk: c.Risk, Mutating: c.Mutating,
		Permission: c.Permission, ResourceKind: c.ResourceKind, Impact: c.Impact, InputSchema: c.ToolSchema(),
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, core.Errorf(core.CodeResourceNotFound, "no route for %s %s", r.Method, r.URL.Path))
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version.Version})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func session(r *http.Request) (string, *core.Error) {
	s := r.Header.Get(SessionHeader)
	if s != "" && !sessionPattern.MatchString(s) {
		return "", core.Errorf(core.CodeInvalidArgument, "%s must match %s", SessionHeader, sessionPattern)
	}
	return s, nil
}

func claimedActor(r *http.Request, fallback string) string {
	claimed := r.Header.Get(ActorHeader)
	if claimed == "" || !sessionPattern.MatchString(claimed) {
		return fallback
	}
	return fallback + " (claims " + claimed + ")"
}

func decode(w http.ResponseWriter, r *http.Request, v any) *core.Error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return core.Errorf(core.CodeInvalidArgument, "invalid request body: %v", err)
	}
	return nil
}

func intParam(v string) (int, *core.Error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, core.Errorf(core.CodeInvalidArgument, "invalid integer parameter %q", v)
	}
	return n, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func writeOutcome(w http.ResponseWriter, out *engine.Outcome, err error) {
	if err != nil {
		writeError(w, core.AsError(err))
		return
	}
	status := http.StatusOK
	if out.Status == engine.StatusApprovalRequired || out.Status == engine.StatusInProgress {
		status = http.StatusAccepted
	}
	writeJSON(w, status, out)
}

func writeError(w http.ResponseWriter, err *core.Error) {
	if n, ok := err.Details["retry_after_seconds"].(int); ok && n > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(n))
	}
	writeJSON(w, err.Code.HTTPStatus(), ErrorBody{Error: err})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func logRequests(log *slog.Logger, api string, next http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Debug("http request", "api", api, "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

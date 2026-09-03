package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

// Reserved top-level tool arguments for mutating capabilities. Transports
// strip them before the capability's own arguments are bound.
const (
	ArgReason         = "reason"
	ArgIdempotencyKey = "idempotency_key"
)

// Capability is a single typed, permissioned operation (spec §8).
//
// Capabilities must be created with Define so that argument binding and
// validation are always wired up.
type Capability struct {
	// ID is the dotted capability identifier, e.g. "service.restart".
	ID string
	// Tool is the MCP tool name, e.g. "service_restart".
	Tool string
	// Description is shown to agents.
	Description string
	// Impact is a trusted, human-readable description of side effects shown
	// to approvers. Required for mutating capabilities.
	Impact string
	Risk   Risk
	// Permission required by policy. Read capabilities use "<domain>.read";
	// mutating capabilities use their own ID.
	Permission string
	Mutating   bool
	// Timeout bounds execution. Zero means the registry default.
	Timeout time.Duration
	// ResourceKind names the kind of resource the capability targets (e.g.
	// "service"), enabling resource-scoped policy. Empty if none.
	ResourceKind string
	// AlwaysAllowed bypasses policy. Only for built-in capabilities that are
	// scoped to the caller's own data, such as request.status.
	AlwaysAllowed bool
	// InputSchema describes the capability's own arguments. Inferred from the
	// input type by Define when nil.
	InputSchema *jsonschema.Schema

	bind func(raw json.RawMessage) (*Invocation, error)
}

// Invocation is a validated, ready-to-run capability call.
type Invocation struct {
	// Resource is the normalized target resource, or "" if not applicable.
	Resource string
	// Args are the normalized arguments, canonical for hashing.
	Args json.RawMessage
	run  func(ctx context.Context) (any, error)
}

// Run executes the invocation.
func (i *Invocation) Run(ctx context.Context) (any, error) { return i.run(ctx) }

// Bind parses and validates raw arguments.
func (c *Capability) Bind(raw json.RawMessage) (*Invocation, error) {
	if c.bind == nil {
		return nil, Errorf(CodeExecutionFailed, "capability %s is not bound", c.ID)
	}
	return c.bind(raw)
}

// Define builds a capability whose arguments decode into In. validate may
// normalize the input in place and returns the target resource; run performs
// the operation. Either error may be a *Error; other validate errors are
// reported as INVALID_ARGUMENT.
func Define[In any](c Capability, validate func(*In) (string, error), run func(context.Context, In) (any, error)) Capability {
	if c.InputSchema == nil {
		c.InputSchema = SchemaFor[In](nil)
	}
	resolved, err := c.InputSchema.Resolve(nil)
	if err != nil {
		panic(fmt.Sprintf("capability %s: invalid input schema: %v", c.ID, err))
	}
	c.bind = func(raw json.RawMessage) (*Invocation, error) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
			raw = []byte("{}")
		}
		var instance any
		if err := json.Unmarshal(raw, &instance); err != nil {
			return nil, Errorf(CodeInvalidArgument, "arguments are not valid JSON: %v", err)
		}
		if _, ok := instance.(map[string]any); !ok {
			return nil, Errorf(CodeInvalidArgument, "arguments must be a JSON object")
		}
		if err := resolved.Validate(instance); err != nil {
			return nil, Errorf(CodeInvalidArgument, "%v", err)
		}
		var in In
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			return nil, Errorf(CodeInvalidArgument, "invalid arguments: %v", err)
		}
		var resource string
		if validate != nil {
			resource, err = validate(&in)
			if err != nil {
				var e *Error
				if errors.As(err, &e) {
					return nil, e
				}
				return nil, Errorf(CodeInvalidArgument, "%v", err)
			}
		}
		normalized, err := json.Marshal(in)
		if err != nil {
			return nil, Errorf(CodeExecutionFailed, "normalize arguments: %v", err)
		}
		return &Invocation{
			Resource: resource,
			Args:     normalized,
			run:      func(ctx context.Context) (any, error) { return run(ctx, in) },
		}, nil
	}
	return c
}

// SchemaFor infers an input schema from In. tweak, if non-nil, may adjust the
// properties (descriptions, enums, bounds) of the inferred object schema.
func SchemaFor[In any](tweak func(props map[string]*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("infer schema: %v", err))
	}
	if s.Properties == nil {
		s.Properties = map[string]*jsonschema.Schema{}
	}
	if tweak != nil {
		tweak(s.Properties)
	}
	return s
}

// ToolSchema returns the schema advertised to agents: the capability's own
// input schema plus the reserved reason/idempotency_key arguments for
// mutating capabilities.
func (c *Capability) ToolSchema() *jsonschema.Schema {
	s := c.InputSchema.CloneSchemas()
	if !c.Mutating {
		return s
	}
	if s.Properties == nil {
		s.Properties = map[string]*jsonschema.Schema{}
	}
	s.Properties[ArgReason] = &jsonschema.Schema{
		Type:        "string",
		Description: "Why this action is needed. Shown to the human approver.",
		MaxLength:   Ptr(500),
	}
	s.Properties[ArgIdempotencyKey] = &jsonschema.Schema{
		Type:        "string",
		Description: "Optional key that makes retries of this request safe.",
		MaxLength:   Ptr(128),
	}
	return s
}

// Ptr returns a pointer to v.
func Ptr[T any](v T) *T { return &v }

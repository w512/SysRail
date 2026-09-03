package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

type unitArgs struct {
	Name  string `json:"name" jsonschema:"unit name"`
	Lines int    `json:"lines,omitempty"`
}

func unitCapability(mutating bool) Capability {
	c := Capability{
		ID: "service.status", Tool: "service_get_status", Description: "status",
		Risk: RiskRead, Permission: "service.read", ResourceKind: "service",
	}
	if mutating {
		c = Capability{
			ID: "service.restart", Tool: "service_restart", Description: "restart",
			Impact: "brief interruption", Risk: RiskLow, Permission: "service.restart",
			Mutating: true, ResourceKind: "service",
		}
	}
	return Define(c,
		func(in *unitArgs) (string, error) {
			if strings.HasPrefix(in.Name, "-") {
				return "", fmt.Errorf("bad name")
			}
			if !strings.HasSuffix(in.Name, ".service") {
				in.Name += ".service"
			}
			return in.Name, nil
		},
		func(_ context.Context, in unitArgs) (any, error) {
			return map[string]any{"name": in.Name}, nil
		})
}

func TestBind(t *testing.T) {
	c := unitCapability(false)
	tests := []struct {
		name     string
		raw      string
		code     Code
		resource string
		args     string
	}{
		{name: "normalizes", raw: `{"name":"nginx"}`, resource: "nginx.service", args: `{"name":"nginx.service"}`},
		{name: "keeps optional", raw: `{"name":"a.service","lines":5}`, resource: "a.service", args: `{"name":"a.service","lines":5}`},
		{name: "missing required", raw: `{}`, code: CodeInvalidArgument},
		{name: "null means empty", raw: `null`, code: CodeInvalidArgument},
		{name: "unknown field", raw: `{"name":"a","extra":1}`, code: CodeInvalidArgument},
		{name: "wrong type", raw: `{"name":5}`, code: CodeInvalidArgument},
		{name: "not an object", raw: `["a"]`, code: CodeInvalidArgument},
		{name: "invalid json", raw: `{"name":`, code: CodeInvalidArgument},
		{name: "validator error", raw: `{"name":"-x"}`, code: CodeInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv, err := c.Bind(json.RawMessage(tt.raw))
			if tt.code != "" {
				var e *Error
				if !errors.As(err, &e) || e.Code != tt.code {
					t.Fatalf("got err %v, want code %s", err, tt.code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if inv.Resource != tt.resource || string(inv.Args) != tt.args {
				t.Fatalf("got resource %q args %s", inv.Resource, inv.Args)
			}
			out, err := inv.Run(context.Background())
			if err != nil || out.(map[string]any)["name"] != tt.resource {
				t.Fatalf("run: %v %v", out, err)
			}
		})
	}
}

func TestToolSchemaAddsReservedArgsForMutations(t *testing.T) {
	read := unitCapability(false)
	if _, ok := read.ToolSchema().Properties[ArgReason]; ok {
		t.Fatal("read capability must not expose reason")
	}
	mut := unitCapability(true)
	s := mut.ToolSchema()
	if _, ok := s.Properties[ArgReason]; !ok {
		t.Fatal("mutating capability must expose reason")
	}
	if _, ok := s.Properties[ArgIdempotencyKey]; !ok {
		t.Fatal("mutating capability must expose idempotency_key")
	}
	if _, ok := mut.InputSchema.Properties[ArgReason]; ok {
		t.Fatal("ToolSchema must not modify the input schema")
	}
}

func TestRegistryValidation(t *testing.T) {
	valid := func() Capability { return unitCapability(false) }
	tests := []struct {
		name   string
		mutate func(*Capability)
		want   string
	}{
		{"bad id", func(c *Capability) { c.ID = "Service" }, "id must be"},
		{"bad tool", func(c *Capability) { c.Tool = "getStatus" }, "tool name"},
		{"generic tool", func(c *Capability) { c.Tool = "shell_exec" }, "generic execution"},
		{"generic id", func(c *Capability) { c.ID = "system.run" }, "generic execution"},
		{"no description", func(c *Capability) { c.Description = " " }, "description"},
		{"bad risk", func(c *Capability) { c.Risk = "huge" }, "unknown risk"},
		{"read with risk", func(c *Capability) { c.Risk = RiskLow }, "non-mutating"},
		{"mutating read risk", func(c *Capability) { c.Mutating = true; c.Impact = "x"; c.Permission = c.ID }, "risk low or higher"},
		{"mutating no impact", func(c *Capability) { c.Mutating = true; c.Risk = RiskLow; c.Permission = c.ID }, "impact"},
		{"mutating wrong permission", func(c *Capability) {
			c.Mutating = true
			c.Risk = RiskLow
			c.Impact = "x"
			c.Permission = "service.write"
		}, "must equal its id"},
		{"read wrong permission", func(c *Capability) { c.Permission = "service.status" }, "<domain>.read"},
		{"no permission", func(c *Capability) { c.Permission = "" }, "permission is required"},
		{"always allowed with permission", func(c *Capability) { c.AlwaysAllowed = true }, "always-allowed"},
		{"too long timeout", func(c *Capability) { c.Timeout = time.Hour }, "timeout"},
		{"reserved arg", func(c *Capability) {
			c.InputSchema = c.InputSchema.CloneSchemas()
			c.InputSchema.Properties[ArgReason] = &jsonschema.Schema{Type: "string"}
		}, "reserved"},
		{"not defined", func(c *Capability) { c.bind = nil }, "core.Define"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(&c)
			_, err := NewRegistry(RegistryOptions{}, c)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestRegistryDefaultsAndLookup(t *testing.T) {
	r, err := NewRegistry(RegistryOptions{ReadTimeout: 3 * time.Second, MutatingTimeout: 7 * time.Second},
		unitCapability(false), unitCapability(true))
	if err != nil {
		t.Fatal(err)
	}
	read, ok := r.ByID("service.status")
	if !ok || read.Timeout != 3*time.Second {
		t.Fatalf("read capability: %v %v", ok, read)
	}
	mut, ok := r.ByTool("service_restart")
	if !ok || mut.Timeout != 7*time.Second {
		t.Fatalf("mutating capability: %v %v", ok, mut)
	}
	perms := r.Permissions()
	if !perms["service.read"]["service"] || !perms["service.restart"]["service"] {
		t.Fatalf("permissions: %v", perms)
	}
	if len(r.All()) != 2 {
		t.Fatalf("all: %d", len(r.All()))
	}
}

func TestRegistryRejectsDuplicates(t *testing.T) {
	_, err := NewRegistry(RegistryOptions{}, unitCapability(false), unitCapability(false))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("got %v", err)
	}
}

func TestAsError(t *testing.T) {
	if e := AsError(context.DeadlineExceeded); e.Code != CodeTimeout || !e.Retryable {
		t.Fatalf("deadline: %+v", e)
	}
	if e := AsError(fmt.Errorf("wrap: %w", Errorf(CodeConflict, "x"))); e.Code != CodeConflict {
		t.Fatalf("wrapped: %+v", e)
	}
	if e := AsError(errors.New("boom")); e.Code != CodeExecutionFailed || e.Message != "boom" {
		t.Fatalf("plain: %+v", e)
	}
	if AsError(nil) != nil {
		t.Fatal("nil")
	}
	if CodeApprovalRequired.HTTPStatus() != 202 || CodePermissionDenied.HTTPStatus() != 403 {
		t.Fatal("http status mapping")
	}
}

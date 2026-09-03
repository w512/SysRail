package core

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	capabilityIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$`)
	toolNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z][a-z0-9]*)+$`)
	// Generic execution verbs weaken the capability model (spec §24, §32).
	forbiddenSegments = map[string]bool{
		"exec": true, "execute": true, "run": true, "command": true, "cmd": true,
		"shell": true, "eval": true, "script": true, "sudo": true,
	}
)

const maxTimeout = 10 * time.Minute

// RegistryOptions configures defaults applied to registered capabilities.
type RegistryOptions struct {
	ReadTimeout     time.Duration
	MutatingTimeout time.Duration
}

// Registry is the single source of truth for available capabilities.
type Registry struct {
	byID   map[string]*Capability
	byTool map[string]*Capability
	order  []*Capability
}

// NewRegistry validates and indexes capabilities. Any invalid or duplicate
// capability is an error.
func NewRegistry(opts RegistryOptions, caps ...Capability) (*Registry, error) {
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 10 * time.Second
	}
	if opts.MutatingTimeout <= 0 {
		opts.MutatingTimeout = 60 * time.Second
	}
	r := &Registry{byID: map[string]*Capability{}, byTool: map[string]*Capability{}}
	var errs []error
	for i := range caps {
		c := caps[i]
		if c.Timeout == 0 {
			c.Timeout = opts.ReadTimeout
			if c.Mutating {
				c.Timeout = opts.MutatingTimeout
			}
		}
		if err := validateCapability(&c); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := r.byID[c.ID]; dup {
			errs = append(errs, fmt.Errorf("capability %s: duplicate id", c.ID))
			continue
		}
		if _, dup := r.byTool[c.Tool]; dup {
			errs = append(errs, fmt.Errorf("capability %s: duplicate tool name %s", c.ID, c.Tool))
			continue
		}
		r.byID[c.ID] = &c
		r.byTool[c.Tool] = &c
		r.order = append(r.order, &c)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return r, nil
}

func validateCapability(c *Capability) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("capability %s: %s", c.ID, fmt.Sprintf(format, args...))
	}
	if !capabilityIDPattern.MatchString(c.ID) {
		return fail("id must be dotted lowercase, e.g. service.restart")
	}
	if !toolNamePattern.MatchString(c.Tool) || len(c.Tool) > 64 {
		return fail("tool name %q must match <domain>_<verb>[_<object>]", c.Tool)
	}
	for _, seg := range strings.FieldsFunc(c.ID+"_"+c.Tool, func(r rune) bool { return r == '.' || r == '_' }) {
		if forbiddenSegments[seg] {
			return fail("generic execution name segment %q is not allowed", seg)
		}
	}
	if strings.TrimSpace(c.Description) == "" {
		return fail("description is required")
	}
	if !c.Risk.Valid() {
		return fail("unknown risk %q", c.Risk)
	}
	if c.Mutating && c.Risk == RiskRead {
		return fail("mutating capability must have risk low or higher")
	}
	if !c.Mutating && c.Risk != RiskRead {
		return fail("non-mutating capability must have risk read")
	}
	if c.Mutating && strings.TrimSpace(c.Impact) == "" {
		return fail("mutating capability must describe its impact")
	}
	switch {
	case c.AlwaysAllowed:
		if c.Mutating || c.Permission != "" {
			return fail("always-allowed capabilities must be read-only and have no permission")
		}
	case c.Permission == "":
		return fail("permission is required")
	case c.Mutating && c.Permission != c.ID:
		return fail("mutating capability permission must equal its id")
	case !c.Mutating && !strings.HasSuffix(c.Permission, ".read"):
		return fail("read capability permission must be <domain>.read")
	}
	if c.Timeout <= 0 || c.Timeout > maxTimeout {
		return fail("timeout must be in (0, %s]", maxTimeout)
	}
	if c.InputSchema == nil || c.InputSchema.Type != "object" {
		return fail("input schema must be an object")
	}
	for _, reserved := range []string{ArgReason, ArgIdempotencyKey} {
		if _, ok := c.InputSchema.Properties[reserved]; ok {
			return fail("argument name %q is reserved", reserved)
		}
	}
	if c.bind == nil {
		return fail("must be created with core.Define")
	}
	return nil
}

// ByID looks up a capability by its dotted ID.
func (r *Registry) ByID(id string) (*Capability, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// ByTool looks up a capability by its MCP tool name.
func (r *Registry) ByTool(tool string) (*Capability, bool) {
	c, ok := r.byTool[tool]
	return c, ok
}

// All returns capabilities in registration order.
func (r *Registry) All() []*Capability { return r.order }

// Permissions returns the set of permissions referenced by registered
// capabilities, mapped to the resource kinds they can be scoped to.
func (r *Registry) Permissions() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, c := range r.order {
		if c.Permission == "" {
			continue
		}
		if out[c.Permission] == nil {
			out[c.Permission] = map[string]bool{}
		}
		if c.ResourceKind != "" {
			out[c.Permission][c.ResourceKind] = true
		}
	}
	return out
}

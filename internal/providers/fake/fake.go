// Package fake is an in-memory provider used to test the core pipeline and
// transports without touching the host.
package fake

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/w512/SysRail/internal/core"
)

// Provider is a fake provider. Restart counts are recorded per resource.
type Provider struct {
	mu       sync.Mutex
	restarts map[string]int
}

// New returns a fake provider.
func New() *Provider { return &Provider{restarts: map[string]int{}} }

// Name implements providers.Provider.
func (p *Provider) Name() string { return "fake" }

// Restarts returns how many times widget was restarted.
func (p *Provider) Restarts(widget string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.restarts[widget]
}

type statusArgs struct {
	Value string `json:"value,omitempty" jsonschema:"value to echo back"`
}

type slowArgs struct {
	Millis int `json:"millis" jsonschema:"how long to sleep"`
}

type failArgs struct {
	Code string `json:"code" jsonschema:"error code to return"`
}

type widgetArgs struct {
	Name string `json:"name" jsonschema:"widget name"`
}

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() []core.Capability {
	return []core.Capability{
		core.Define(core.Capability{
			ID: "fake.status", Tool: "fake_get_status", Description: "Echo a value.",
			Risk: core.RiskRead, Permission: "fake.read",
		}, nil, func(_ context.Context, in statusArgs) (any, error) {
			return map[string]any{"value": in.Value, "note": "db password=hunter22"}, nil
		}),
		core.Define(core.Capability{
			ID: "fake.slow", Tool: "fake_get_slow", Description: "Sleep, honoring cancellation.",
			Risk: core.RiskRead, Permission: "fake.read", Timeout: 200 * time.Millisecond,
		}, nil, func(ctx context.Context, in slowArgs) (any, error) {
			select {
			case <-time.After(time.Duration(in.Millis) * time.Millisecond):
				return map[string]any{"slept_ms": in.Millis}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
		core.Define(core.Capability{
			ID: "fake.failure", Tool: "fake_get_failure", Description: "Fail with the given code.",
			Risk: core.RiskRead, Permission: "fake.read",
		}, nil, func(_ context.Context, in failArgs) (any, error) {
			if in.Code == "plain" {
				return nil, fmt.Errorf("plain failure token=abc123")
			}
			return nil, core.Errorf(core.Code(in.Code), "requested failure")
		}),
		core.Define(core.Capability{
			ID: "fake.restart", Tool: "fake_restart", Description: "Restart a widget.",
			Impact: "The widget is briefly unavailable.", Risk: core.RiskLow,
			Permission: "fake.restart", Mutating: true, ResourceKind: "widget",
		}, func(in *widgetArgs) (string, error) {
			in.Name = strings.TrimSpace(in.Name)
			if in.Name == "" || strings.HasPrefix(in.Name, "-") {
				return "", fmt.Errorf("invalid widget name %q", in.Name)
			}
			if in.Name == "protected" {
				return "", core.Errorf(core.CodePermissionDenied, "widget %q is protected", in.Name)
			}
			return in.Name, nil
		}, func(_ context.Context, in widgetArgs) (any, error) {
			if in.Name == "missing" {
				return nil, core.Errorf(core.CodeResourceNotFound, "widget %q not found", in.Name)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			p.restarts[in.Name]++
			return map[string]any{"widget": in.Name, "restarts": p.restarts[in.Name]}, nil
		}),
	}
}

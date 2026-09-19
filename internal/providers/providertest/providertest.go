// Package providertest is the contract test every provider must pass
// (spec §41.2): advertised capabilities are valid and executable, results are
// JSON objects, and failures are structured errors.
package providertest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/providers"
)

// Options tunes the contract run.
type Options struct {
	// Examples maps capability ID to arguments used to execute it. Every
	// read-only capability needs one; mutating capabilities are executed
	// only if they have an example.
	Examples map[string]string
	// Timeout bounds each execution. Default 30s.
	Timeout time.Duration
}

// Run checks p against the provider contract.
func Run(t *testing.T, p providers.Provider, opts Options) {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if p.Name() == "" {
		t.Fatal("provider has no name")
	}
	caps := p.Capabilities()
	if len(caps) == 0 {
		t.Fatal("provider advertises no capabilities")
	}
	if _, err := core.NewRegistry(core.RegistryOptions{}, caps...); err != nil {
		t.Fatalf("capabilities are invalid: %v", err)
	}
	for _, c := range caps {
		t.Run(c.ID, func(t *testing.T) {
			_, err := c.Bind(json.RawMessage(`{"__contract_unknown__":1}`))
			var cerr *core.Error
			if !errors.As(err, &cerr) || cerr.Code != core.CodeInvalidArgument {
				t.Errorf("unknown argument must be rejected with INVALID_ARGUMENT, got %v", err)
			}

			example, ok := opts.Examples[c.ID]
			if !ok {
				if !c.Mutating {
					t.Fatalf("no example arguments for read capability %s", c.ID)
				}
				return
			}
			inv, err := c.Bind(json.RawMessage(example))
			if err != nil {
				t.Fatalf("example %s does not bind: %v", example, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
			defer cancel()
			out, err := inv.Run(ctx)
			if err != nil {
				if !errors.As(err, &cerr) {
					t.Fatalf("execution failed with an unstructured error: %v", err)
				}
				t.Logf("structured error: %v", cerr)
				return
			}
			b, err := json.Marshal(out)
			if err != nil {
				t.Fatalf("result does not encode as JSON: %v", err)
			}
			if !bytes.HasPrefix(b, []byte("{")) {
				t.Fatalf("result must be a JSON object, got %s", b)
			}
		})
	}
}

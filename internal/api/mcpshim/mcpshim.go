// Package mcpshim is the stdio MCP server launched by agent hosts. It holds no
// policy or privileges: it fetches the capabilities the agent may reach from
// the daemon, registers them as MCP tools and forwards every call to the
// daemon's agent API.
package mcpshim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/w512/SysRail/internal/api/httpapi"
	"github.com/w512/SysRail/internal/client"
	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/engine"
	"github.com/w512/SysRail/internal/version"
)

// Instructions are sent to the agent when it connects.
const Instructions = `SysRail exposes typed, policy-controlled operations on this Linux host. ` +
	`There is no shell and no generic command execution. Every call is audited. ` +
	`Mutating tools may require human approval: when a result has status "approval_required", ` +
	`tell the user and poll request_get_status with the request_id (use wait_seconds up to 30) ` +
	`until the status is executed, failed, denied or expired. Pass a short "reason" with ` +
	`mutating calls; it is shown to the approver. Errors are structured with a code such as ` +
	`PERMISSION_DENIED; do not retry denied requests.`

// New builds an MCP server for the agent authenticated by c.
func New(ctx context.Context, c *client.Client) (*mcp.Server, error) {
	var caps struct {
		Agent        string                   `json:"agent"`
		Capabilities []httpapi.CapabilityInfo `json:"capabilities"`
	}
	if _, err := c.Do(ctx, http.MethodGet, "/v1/capabilities", nil, &caps); err != nil {
		return nil, fmt.Errorf("fetch capabilities: %w", err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "sysrail", Version: version.Version},
		&mcp.ServerOptions{Instructions: Instructions})
	for _, ci := range caps.Capabilities {
		s.AddTool(tool(ci), handler(c, ci))
	}
	return s, nil
}

func tool(ci httpapi.CapabilityInfo) *mcp.Tool {
	desc := ci.Description
	ann := &mcp.ToolAnnotations{ReadOnlyHint: !ci.Mutating, IdempotentHint: !ci.Mutating, OpenWorldHint: core.Ptr(false)}
	if ci.Mutating {
		desc += fmt.Sprintf(" Changes system state (risk: %s). May require human approval.", ci.Risk)
		if ci.Impact != "" {
			desc += " Impact: " + ci.Impact
		}
		ann.DestructiveHint = core.Ptr(core.Risk(ci.Risk).Rank() >= core.RiskMedium.Rank())
	}
	return &mcp.Tool{Name: ci.Tool, Description: desc, InputSchema: ci.InputSchema, Annotations: ann}
}

func handler(c *client.Client, ci httpapi.CapabilityInfo) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		body := httpapi.ExecuteRequest{Capability: ci.ID}
		args := map[string]json.RawMessage{}
		if raw := bytes.TrimSpace(req.Params.Arguments); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
			if err := json.Unmarshal(raw, &args); err != nil {
				return errorResult(core.Errorf(core.CodeInvalidArgument, "arguments must be a JSON object")), nil
			}
		}
		if ci.Mutating {
			for name, dst := range map[string]*string{core.ArgReason: &body.Reason, core.ArgIdempotencyKey: &body.IdempotencyKey} {
				if v, ok := args[name]; ok {
					if err := json.Unmarshal(v, dst); err != nil {
						return errorResult(core.Errorf(core.CodeInvalidArgument, "%s must be a string", name)), nil
					}
					delete(args, name)
				}
			}
		}
		body.Arguments, _ = json.Marshal(args)

		var out engine.Outcome
		if _, err := c.Do(ctx, http.MethodPost, "/v1/execute", body, &out); err != nil {
			var cerr *core.Error
			if !errors.As(err, &cerr) {
				cerr = core.Errorf(core.CodeExecutionFailed, "%v", err)
			}
			return errorResult(cerr), nil
		}
		switch out.Status {
		case engine.StatusSuccess:
			return &mcp.CallToolResult{
				StructuredContent: out.Result,
				Content:           []mcp.Content{&mcp.TextContent{Text: string(out.Result)}},
			}, nil
		default:
			pending := map[string]any{
				"status":     out.Status,
				"request_id": out.RequestID,
				"message": "A human must approve this request (sysrail approvals approve " + out.RequestID +
					"). Poll request_get_status with this request_id to get the outcome.",
			}
			if out.ExpiresAt != nil {
				pending["expires_at"] = out.ExpiresAt
			}
			text, _ := json.Marshal(pending)
			return &mcp.CallToolResult{
				StructuredContent: pending,
				Content:           []mcp.Content{&mcp.TextContent{Text: string(text)}},
			}, nil
		}
	}
}

func errorResult(e *core.Error) *mcp.CallToolResult {
	body := map[string]any{"error": e}
	text, _ := json.Marshal(body)
	return &mcp.CallToolResult{
		IsError:           true,
		StructuredContent: body,
		Content:           []mcp.Content{&mcp.TextContent{Text: string(text)}},
	}
}

package mcpshim

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/w512/SysRail/internal/api/httpapi"
	"github.com/w512/SysRail/internal/client"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/testutil"
)

func connect(t *testing.T, env *testutil.Env, agent string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := httptest.NewServer(httpapi.NewAgentHandler(env.Engine, env.Auth, nil))
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, env.Tokens[agent])
	if err != nil {
		t.Fatal(err)
	}
	c.SetHeader(httpapi.SessionHeader, "sess_test")
	server, err := New(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var m map[string]any
	json.Unmarshal(b, &m)
	return res, m
}

func TestToolsReflectPolicy(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Policy)
	cs := connect(t, env, "agent")
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		tools[tl.Name] = tl
	}
	for _, name := range []string{"fake_get_status", "fake_restart", "request_get_status"} {
		if tools[name] == nil {
			t.Fatalf("missing tool %s", name)
		}
	}
	restart := tools["fake_restart"]
	if restart.Annotations.ReadOnlyHint || !strings.Contains(restart.Description, "approval") {
		t.Fatalf("mutating tool metadata: %+v %q", restart.Annotations, restart.Description)
	}
	if !tools["fake_get_status"].Annotations.ReadOnlyHint {
		t.Fatal("read tool not marked read-only")
	}
	schema, _ := json.Marshal(restart.InputSchema)
	if !strings.Contains(string(schema), `"reason"`) {
		t.Fatalf("schema lacks reason: %s", schema)
	}

	other := connect(t, env, "other")
	res, _ = other.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		if tl.Name == "fake_restart" {
			t.Fatal("tool the agent can never use was advertised")
		}
	}
}

func TestCallsGoThroughTheDaemon(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Policy)
	cs := connect(t, env, "agent")

	res, body := callTool(t, cs, "fake_get_status", map[string]any{"value": "hi"})
	if res.IsError || body["value"] != "hi" || strings.Contains(body["note"].(string), "hunter22") {
		t.Fatalf("read: %+v %v", res, body)
	}

	res, body = callTool(t, cs, "fake_get_status", map[string]any{"bogus": 1})
	if !res.IsError || body["error"].(map[string]any)["code"] != "INVALID_ARGUMENT" {
		t.Fatalf("invalid args: %+v %v", res, body)
	}

	res, body = callTool(t, cs, "fake_restart", map[string]any{"name": "w1", "reason": "health check failed"})
	if res.IsError || body["status"] != "approval_required" || body["request_id"] == nil {
		t.Fatalf("approval: %+v %v", res, body)
	}
	id := body["request_id"].(string)
	if env.Fake.Restarts("w1") != 0 {
		t.Fatal("ran before approval")
	}
	req, err := env.Engine.Approve(context.Background(), id, "root", "")
	if err != nil || req.Reason != "health check failed" {
		t.Fatalf("approve: %v %+v", err, req)
	}
	_, body = callTool(t, cs, "request_get_status", map[string]any{"request_id": id, "wait_seconds": 1})
	if body["status"] != "executed" || env.Fake.Restarts("w1") != 1 {
		t.Fatalf("status: %v", body)
	}

	res, body = callTool(t, cs, "fake_restart", map[string]any{"name": "auto", "idempotency_key": "k1"})
	if res.IsError || body["restarts"] != 1.0 {
		t.Fatalf("allowed mutation: %+v %v", res, body)
	}
	callTool(t, cs, "fake_restart", map[string]any{"name": "auto", "idempotency_key": "k1"})
	if env.Fake.Restarts("auto") != 1 {
		t.Fatal("idempotency key not forwarded")
	}

	recs, _ := env.Store.List(context.Background(), audit.Filter{Limit: 1000})
	if len(recs) == 0 || recs[0].Session != "sess_test" || recs[0].Agent != "agent" {
		t.Fatalf("audit: %+v", recs[0])
	}
}

func TestDeniedCall(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Policy)
	cs := connect(t, env, "other")
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "fake_restart", Arguments: map[string]any{"name": "w"},
	}); err == nil {
		t.Fatal("unadvertised tool was callable")
	}
}

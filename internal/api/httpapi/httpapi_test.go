package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/w512/SysRail/internal/auth"
	"github.com/w512/SysRail/internal/core/audit"
	"github.com/w512/SysRail/internal/testutil"
)

type client struct {
	t     *testing.T
	base  string
	token string
}

func (c client) do(method, path, body string, hdr ...string) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			c.t.Fatalf("%s %s: non-JSON response %q", method, path, raw)
		}
	}
	return resp.StatusCode, out
}

func auditFilterLast() audit.Filter { return audit.Filter{Limit: 1000} }

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func setup(t *testing.T) (*testutil.Env, client, client, client) {
	env := testutil.NewEnv(t, testutil.Policy)
	agentSrv := httptest.NewServer(NewAgentHandler(env.Engine, env.Auth, nil))
	adminSrv := httptest.NewServer(NewAdminHandler(env.Engine, nil, nil))
	t.Cleanup(agentSrv.Close)
	t.Cleanup(adminSrv.Close)
	return env,
		client{t, agentSrv.URL, env.Tokens["agent"]},
		client{t, agentSrv.URL, env.Tokens["other"]},
		client{t, adminSrv.URL, ""}
}

func tools(m map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, c := range m["capabilities"].([]any) {
		ci := c.(map[string]any)
		out[ci["tool"].(string)] = ci
	}
	return out
}

func TestAgentAuthAndCapabilities(t *testing.T) {
	_, agent, other, _ := setup(t)
	anon := client{agent.t, agent.base, ""}
	if code, _ := anon.do("GET", "/v1/health", ""); code != 200 {
		t.Fatalf("health: %d", code)
	}
	if code, body := anon.do("GET", "/v1/capabilities", ""); code != 401 || errCode(body) != "AUTHENTICATION_FAILED" {
		t.Fatalf("anonymous: %d %v", code, body)
	}
	bad := client{agent.t, agent.base, "sysrail_wrong"}
	if code, _ := bad.do("POST", "/v1/execute", `{"capability":"fake.status"}`); code != 401 {
		t.Fatalf("bad token: %d", code)
	}

	_, body := agent.do("GET", "/v1/capabilities", "")
	got := tools(body)
	for _, name := range []string{"fake_get_status", "fake_restart", "request_get_status"} {
		if got[name] == nil {
			t.Fatalf("agent missing %s: %v", name, got)
		}
	}
	props := got["fake_restart"]["input_schema"].(map[string]any)["properties"].(map[string]any)
	if props["reason"] == nil || props["idempotency_key"] == nil {
		t.Fatalf("mutating schema lacks reserved args: %v", props)
	}
	_, body = other.do("GET", "/v1/capabilities", "")
	if tools(body)["fake_restart"] != nil {
		t.Fatal("unreachable tool advertised to other agent")
	}
}

func TestExecute(t *testing.T) {
	env, agent, other, _ := setup(t)
	tests := []struct {
		c      client
		body   string
		status int
		code   string
	}{
		{agent, `{"capability":"fake.status","arguments":{"value":"x"}}`, 200, ""},
		{agent, `{"capability":"fake.restart","arguments":{"name":"w"},"reason":"why"}`, 202, ""},
		{other, `{"capability":"fake.restart","arguments":{"name":"w"}}`, 403, "PERMISSION_DENIED"},
		{agent, `{"capability":"fake.nope"}`, 404, "RESOURCE_NOT_FOUND"},
		{agent, `{"capability":"fake.status","arguments":{"bogus":1}}`, 400, "INVALID_ARGUMENT"},
		{agent, `{"capability":"fake.status","extra":1}`, 400, "INVALID_ARGUMENT"},
		{agent, `not json`, 400, "INVALID_ARGUMENT"},
	}
	for _, tt := range tests {
		status, body := tt.c.do("POST", "/v1/execute", tt.body)
		if status != tt.status || errCode(body) != tt.code {
			t.Errorf("%s: got %d %v, want %d %s", tt.body, status, body, tt.status, tt.code)
		}
	}
	if status, _ := agent.do("POST", "/v1/execute", `{"capability":"fake.status"}`, SessionHeader, "bad session!"); status != 400 {
		t.Fatalf("invalid session accepted: %d", status)
	}
	agent.do("POST", "/v1/execute", `{"capability":"fake.status"}`, SessionHeader, "sess_1")
	recs, _ := env.Store.List(t.Context(), auditFilterLast())
	if recs[len(recs)-1].Session != "sess_1" {
		t.Fatalf("session not recorded: %+v", recs[len(recs)-1])
	}
}

func TestApprovalOverAdminAPI(t *testing.T) {
	env, agent, other, admin := setup(t)
	_, body := agent.do("POST", "/v1/execute", `{"capability":"fake.restart","arguments":{"name":"w"},"reason":"stuck"}`)
	id := body["request_id"].(string)

	if status, _ := other.do("GET", "/v1/requests/"+id, ""); status != 404 {
		t.Fatalf("other agent saw request: %d", status)
	}
	if status, body := agent.do("GET", "/v1/requests/"+id+"?wait=0", ""); status != 200 || body["status"] != "pending" {
		t.Fatalf("agent status: %d %v", status, body)
	}
	if status, _ := agent.do("POST", "/v1/requests/"+id+"/approve", `{}`); status == 200 {
		t.Fatal("agent API must not expose approval")
	}

	_, body = admin.do("GET", "/v1/requests?status=pending", "")
	if reqs := body["requests"].([]any); len(reqs) != 1 || reqs[0].(map[string]any)["reason"] != "stuck" {
		t.Fatalf("pending list: %v", body)
	}
	status, body := admin.do("POST", "/v1/requests/"+id+"/approve", `{"note":"go"}`, ActorHeader, "nick")
	if status != 200 || body["status"] != "executed" || body["decided_by"] != "admin (claims nick)" {
		t.Fatalf("approve: %d %v", status, body)
	}
	if env.Fake.Restarts("w") != 1 {
		t.Fatal("approved request did not run")
	}
	if status, body := admin.do("POST", "/v1/requests/"+id+"/approve", `{}`); status != 409 || errCode(body) != "CONFLICT" {
		t.Fatalf("second approve: %d %v", status, body)
	}
	if status, body := agent.do("GET", "/v1/requests/"+id, ""); status != 200 || body["status"] != "executed" {
		t.Fatalf("agent status after approval: %d %v", status, body)
	}

	_, body = agent.do("POST", "/v1/execute", `{"capability":"fake.restart","arguments":{"name":"x"}}`)
	id2 := body["request_id"].(string)
	if status, body := admin.do("POST", "/v1/requests/"+id2+"/deny", `{"note":"no"}`); status != 200 || body["status"] != "denied" {
		t.Fatalf("deny: %d %v", status, body)
	}
	if status, _ := admin.do("GET", "/v1/requests/req_missing", ""); status != 404 {
		t.Fatalf("missing request: %d", status)
	}

	_, body = admin.do("GET", "/v1/audit?request_id="+id, "")
	if recs := body["records"].([]any); len(recs) != 3 {
		t.Fatalf("audit for request: %v", body)
	}
	if status, _ := admin.do("GET", "/v1/audit?limit=x", ""); status != 400 {
		t.Fatalf("bad limit: %d", status)
	}
}

func TestWithAdminToken(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Policy)
	adminTok, adminHash, _ := auth.NewToken()
	srv := httptest.NewServer(WithAdminToken(
		NewAgentHandler(env.Engine, env.Auth, nil), NewAdminHandler(env.Engine, nil, nil), adminHash))
	t.Cleanup(srv.Close)
	agent := client{t, srv.URL, env.Tokens["agent"]}
	admin := client{t, srv.URL, adminTok}

	_, body := agent.do("POST", "/v1/execute", `{"capability":"fake.restart","arguments":{"name":"w"}}`)
	id := body["request_id"].(string)
	if status, _ := agent.do("GET", "/v1/requests", ""); status == 200 {
		t.Fatal("agent token reached admin list")
	}
	if status, body := admin.do("POST", "/v1/requests/"+id+"/approve", `{}`); status != 200 || body["status"] != "executed" {
		t.Fatalf("admin approve: %d %v", status, body)
	}
}

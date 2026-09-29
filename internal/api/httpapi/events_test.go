package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/testutil"
)

type sseEvent struct {
	id, typ string
	ev      events.Event
}

// stream opens an SSE connection and returns a channel of parsed events.
func stream(t *testing.T, url, token, lastID string) <-chan sseEvent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status %d content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	out := make(chan sseEvent, 32)
	go func() {
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var cur sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "id: "):
				cur.id = line[4:]
			case strings.HasPrefix(line, "event: "):
				cur.typ = line[7:]
			case strings.HasPrefix(line, "data: "):
				json.Unmarshal([]byte(line[6:]), &cur.ev)
			case line == "" && cur.typ != "":
				out <- cur
				cur = sseEvent{}
			}
		}
	}()
	return out
}

func collect(ch <-chan sseEvent, wait time.Duration) []sseEvent {
	var got []sseEvent
	deadline := time.After(wait)
	for {
		select {
		case e := <-ch:
			got = append(got, e)
		case <-deadline:
			return got
		}
	}
}

func TestEventStreamsAreFilteredPerAgent(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Policy)
	agentSrv := httptest.NewServer(NewAgentHandler(env.Engine, env.Auth, nil))
	adminSrv := httptest.NewServer(NewAdminHandler(env.Engine, nil, nil))
	t.Cleanup(agentSrv.Close)
	t.Cleanup(adminSrv.Close)

	agentCh := stream(t, agentSrv.URL+"/v1/events", env.Tokens["agent"], "")
	otherCh := stream(t, agentSrv.URL+"/v1/events", env.Tokens["other"], "")
	adminCh := stream(t, adminSrv.URL+"/v1/events", "", "")
	time.Sleep(50 * time.Millisecond)

	env.Bus.Publish(events.Event{Type: "fake.changed", Source: "test", ResourceKind: "fake", Resource: "x"})
	env.Bus.Publish(events.Event{Type: events.ServiceFailed, Source: "systemd", ResourceKind: "service", Resource: "nginx.service"})
	agent := client{t, agentSrv.URL, env.Tokens["agent"]}
	agent.do("POST", "/v1/execute", `{"capability":"fake.restart","arguments":{"name":"w"}}`)

	types := func(es []sseEvent) string {
		var s []string
		for _, e := range es {
			s = append(s, e.typ)
		}
		return strings.Join(s, " ")
	}
	if got := types(collect(agentCh, 300*time.Millisecond)); got != "fake.changed request.pending" {
		t.Errorf("agent saw %q", got)
	}
	if got := types(collect(otherCh, 100*time.Millisecond)); got != "fake.changed" {
		t.Errorf("other agent saw %q (must not see agent's requests or unreadable services)", got)
	}
	adminEvents := collect(adminCh, 100*time.Millisecond)
	if got := types(adminEvents); got != "fake.changed service.failed request.pending" {
		t.Errorf("admin saw %q", got)
	}

	resumed := stream(t, adminSrv.URL+"/v1/events?types=request.pending", "", adminEvents[0].id)
	if got := collect(resumed, 200*time.Millisecond); len(got) != 1 || got[0].ev.Data["request_id"] == nil {
		t.Errorf("resume with type filter: %+v", got)
	}
}

func TestEventStreamRequiresToken(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Policy)
	srv := httptest.NewServer(NewAgentHandler(env.Engine, env.Auth, nil))
	t.Cleanup(srv.Close)
	if code, _ := (client{t, srv.URL, ""}).do("GET", "/v1/events", ""); code != 401 {
		t.Fatalf("got %d", code)
	}
	if code, _ := (client{t, srv.URL, env.Tokens["agent"]}).do("GET", "/v1/events?since=abc", ""); code != 400 {
		t.Fatalf("bad cursor: %d", code)
	}
}

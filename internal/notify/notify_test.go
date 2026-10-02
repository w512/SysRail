package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/core/request"
	"github.com/w512/SysRail/internal/notify/smtptest"
)

var expires = time.Date(2026, 10, 2, 19, 15, 0, 0, time.UTC)

func testNotifier(chans ...Channel) *Notifier {
	return New(Options{
		Channels: chans, Host: "web1", Retry: []time.Duration{10 * time.Millisecond}, Timeout: 2 * time.Second,
		Lookup: func(_ context.Context, id string) (*request.Request, error) {
			if id != "req_1" {
				return nil, request.ErrNotFound
			}
			return &request.Request{
				ID: "req_1", Agent: "opencode", Capability: "service.restart", Resource: "nginx.service",
				Risk: core.RiskLow, Status: request.Pending, ExpiresAt: &expires,
				Reason: "port 80 is free\x1b[2J; password=hunter22",
			}, nil
		},
		Impact: func(c string) string { return "Brief interruption." },
	})
}

var pendingEvent = events.Event{ID: 7, Type: events.RequestPending, Source: "core", Agent: "opencode",
	ResourceKind: "service", Resource: "nginx.service",
	Data: map[string]any{"request_id": "req_1", "capability": "service.restart", "status": "pending"}}

func TestBuildPending(t *testing.T) {
	m := testNotifier().Build(context.Background(), pendingEvent)
	if m.Title != "SysRail: approval needed on web1" || m.Priority != "high" || m.Type != events.RequestPending {
		t.Fatalf("message: %+v", m)
	}
	for _, want := range []string{
		"opencode requests service.restart on nginx.service (risk: low).",
		"Impact: Brief interruption.",
		"Reason (from the agent, unverified): port 80 is free",
		"Approve: sudo sysrail approvals approve req_1",
		"Deny:    sudo sysrail approvals deny req_1",
		"Expires: ",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("text lacks %q:\n%s", want, m.Text)
		}
	}
	if strings.Contains(m.Text, "hunter22") || strings.Contains(m.Text, "\x1b") {
		t.Fatalf("reason not sanitized:\n%s", m.Text)
	}
	if m.Request == nil || m.Request.ID != "req_1" || m.Request.Risk != "low" || m.Request.ExpiresAt == nil {
		t.Fatalf("request info: %+v", m.Request)
	}
}

func TestBuildOtherEvents(t *testing.T) {
	n := testNotifier()
	ctx := context.Background()
	failed := n.Build(ctx, events.Event{Type: events.RequestFailed, Agent: "opencode", Resource: "x.service",
		Data: map[string]any{"request_id": "req_missing", "capability": "service.start", "status": "failed"}})
	if failed.Title != "SysRail: request failed on web1" || failed.Priority != "high" ||
		!strings.Contains(failed.Text, "service.start on x.service for opencode (req_missing) was failed") {
		t.Fatalf("failed: %+v", failed)
	}
	svc := n.Build(ctx, events.Event{Type: events.ServiceFailed, Resource: "nginx.service",
		Data: map[string]any{"sub_state": "failed", "previous_state": "active"}})
	if svc.Title != "SysRail: nginx.service failed on web1" ||
		svc.Text != "nginx.service entered the failed state (sub-state: failed; previously active)." {
		t.Fatalf("service failed: %+v", svc)
	}
	rec := n.Build(ctx, events.Event{Type: events.ServiceRecovered, Resource: "nginx.service"})
	if rec.Priority != "default" || rec.Text != "nginx.service is active again." {
		t.Fatalf("recovered: %+v", rec)
	}
}

type captured struct {
	path    string
	headers http.Header
	body    string
}

func recorder(t *testing.T, status int, reply string) (*httptest.Server, <-chan captured) {
	t.Helper()
	ch := make(chan captured, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- captured{path: r.URL.Path, headers: r.Header, body: string(b)}
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func TestWebhook(t *testing.T) {
	srv, ch := recorder(t, 204, "")
	w := NewWebhook(srv.URL+"/hook?secret=x", map[string]string{"Authorization": "Bearer abc"}, nil)
	if w.Name() != "webhook "+srv.URL+"/hook" {
		t.Fatalf("name leaks query: %s", w.Name())
	}
	if !w.Wants(events.RequestPending) || w.Wants(events.ServiceFailed) {
		t.Fatal("default subscription must be request.pending only")
	}
	m := testNotifier().Build(context.Background(), pendingEvent)
	if err := w.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	var payload Message
	if err := json.Unmarshal([]byte(got.body), &payload); err != nil {
		t.Fatal(err)
	}
	if got.headers.Get("Authorization") != "Bearer abc" || got.headers.Get("Content-Type") != "application/json" ||
		payload.Request.ID != "req_1" || payload.Event.ID != 7 || payload.Title != m.Title {
		t.Fatalf("webhook request: %+v %+v", got.headers, payload)
	}

	for status, wantRetry := range map[int]bool{500: true, 429: true, 400: false, 401: false} {
		srv, _ := recorder(t, status, "nope")
		err := NewWebhook(srv.URL, nil, nil).Send(context.Background(), m)
		if err == nil || isRetryable(err) != wantRetry {
			t.Errorf("HTTP %d: err %v, retryable %v", status, err, isRetryable(err))
		}
	}
}

func TestNtfy(t *testing.T) {
	srv, ch := recorder(t, 200, `{"id":"x"}`)
	n := NewNtfy(srv.URL+"/sysrail", "tk_secret", []string{events.RequestPending, events.ServiceFailed})
	m := testNotifier().Build(context.Background(), pendingEvent)
	if err := n.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.path != "/sysrail" || got.headers.Get("Title") != m.Title || got.headers.Get("Priority") != "high" ||
		got.headers.Get("Tags") != "raising_hand" || got.headers.Get("Authorization") != "Bearer tk_secret" ||
		got.body != m.Text {
		t.Fatalf("ntfy request: %+v", got)
	}
	if !n.Wants(events.ServiceFailed) {
		t.Fatal("configured events ignored")
	}
}

func TestTelegram(t *testing.T) {
	srv, ch := recorder(t, 200, `{"ok":true,"result":{}}`)
	tg := NewTelegram("123:SECRET", "-1001", srv.URL, nil)
	m := testNotifier().Build(context.Background(), pendingEvent)
	if err := tg.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	var body struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
		LPO    struct {
			Disabled bool `json:"is_disabled"`
		} `json:"link_preview_options"`
	}
	json.Unmarshal([]byte(got.body), &body)
	if got.path != "/bot123:SECRET/sendMessage" || body.ChatID != "-1001" || !body.LPO.Disabled ||
		!strings.HasPrefix(body.Text, m.Title+"\n\n") {
		t.Fatalf("telegram request: %s %s", got.path, got.body)
	}
	if strings.Contains(tg.Name(), "SECRET") {
		t.Fatalf("name leaks token: %s", tg.Name())
	}

	bad, _ := recorder(t, 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`)
	err := NewTelegram("123:SECRET", "1", bad.URL, nil).Send(context.Background(), m)
	if err == nil || err.Error() != "telegram: Bad Request: chat not found" || isRetryable(err) {
		t.Fatalf("API error: %v", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	err = NewTelegram("123:SECRET", "1", "http://"+addr, nil).Send(context.Background(), m)
	if err == nil || !isRetryable(err) || strings.Contains(cleanErr(err).Error(), "SECRET") {
		t.Fatalf("network error must be retryable and must not contain the token: %v", cleanErr(err))
	}
}

func TestEmail(t *testing.T) {
	srv, err := smtptest.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	e := NewEmail(EmailConfig{Host: "127.0.0.1", Port: srv.Addr().Port, TLS: TLSNone,
		From: "SysRail <sysrail@example.com>", To: []string{"ops@example.com", "nick@example.com"}})
	m := testNotifier().Build(context.Background(), pendingEvent)
	if err := e.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 || msgs[0].From != "sysrail@example.com" || len(msgs[0].To) != 2 {
		t.Fatalf("envelope: %+v", msgs)
	}
	head, body, _ := strings.Cut(msgs[0].Data, "\r\n\r\n")
	subject := ""
	for _, l := range strings.Split(head, "\r\n") {
		if s, ok := strings.CutPrefix(l, "Subject: "); ok {
			subject, _ = new(mime.WordDecoder).DecodeHeader(s)
		}
	}
	decoded, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if subject != m.Title || !strings.Contains(head, "X-SysRail-Event: request.pending") ||
		!strings.Contains(string(decoded), "sudo sysrail approvals approve req_1") {
		t.Fatalf("message:\n%s\n%s", head, decoded)
	}

	srv.RejectCode = "550"
	if err := e.Send(context.Background(), m); err == nil || isRetryable(err) {
		t.Fatalf("5xx must be permanent: %v", err)
	}
	srv.RejectCode = "451"
	if err := e.Send(context.Background(), m); err == nil || !isRetryable(err) {
		t.Fatalf("4xx must be retryable: %v", err)
	}

	srv.RejectCode = ""
	strict := NewEmail(EmailConfig{Host: "127.0.0.1", Port: srv.Addr().Port, From: "a@example.com", To: []string{"b@example.com"}})
	if err := strict.Send(context.Background(), m); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("starttls must not silently downgrade: %v", err)
	}
}

type fakeChannel struct {
	subscription
	name  string
	fail  int
	mu    sync.Mutex
	calls int
	got   []*Message
}

func (f *fakeChannel) Name() string { return f.name }

func (f *fakeChannel) Send(_ context.Context, m *Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.fail {
		return retryable(errors.New("temporary"))
	}
	f.got = append(f.got, m)
	return nil
}

func (f *fakeChannel) snapshot() (int, []*Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, append([]*Message(nil), f.got...)
}

func TestRunDispatchesWithRetries(t *testing.T) {
	ok := &fakeChannel{subscription: newSubscription(nil), name: "ok"}
	flaky := &fakeChannel{subscription: newSubscription(nil), name: "flaky", fail: 1}
	services := &fakeChannel{subscription: newSubscription([]string{events.ServiceFailed}), name: "services"}
	n := testNotifier(ok, flaky, services)
	bus := events.NewBus(10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx, bus); close(done) }()
	time.Sleep(20 * time.Millisecond)
	bus.Publish(pendingEvent)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, a := ok.snapshot()
		_, b := flaky.snapshot()
		if len(a) == 1 && len(b) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if _, got := ok.snapshot(); len(got) != 1 || got[0].Request.ID != "req_1" {
		t.Fatalf("ok channel: %+v", got)
	}
	if calls, got := flaky.snapshot(); calls != 2 || len(got) != 1 {
		t.Fatalf("flaky channel: %d calls, %d delivered", calls, len(got))
	}
	if calls, _ := services.snapshot(); calls != 0 {
		t.Fatal("channel received an event it did not subscribe to")
	}
}

func TestTestSendsToEveryChannel(t *testing.T) {
	ok := &fakeChannel{subscription: newSubscription(nil), name: "ok"}
	bad := &fakeChannel{subscription: newSubscription(nil), name: "bad", fail: 5}
	res := testNotifier(ok, bad).Test(context.Background())
	if len(res) != 2 || res[0].Err != nil || res[1].Err == nil {
		t.Fatalf("results: %+v", res)
	}
	if _, got := ok.snapshot(); got[0].Type != "test" || !strings.Contains(got[0].Title, "test notification") {
		t.Fatalf("test message: %+v", got[0])
	}
}

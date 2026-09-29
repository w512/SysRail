package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/w512/SysRail/internal/core"
	"github.com/w512/SysRail/internal/core/engine"
	"github.com/w512/SysRail/internal/core/events"
	"github.com/w512/SysRail/internal/core/policy"
)

const keepalive = 25 * time.Second

// agentEventFilter lets an agent see its own request events and host events
// about resources it may read.
func agentEventFilter(eng *engine.Engine, agent string) func(events.Event) bool {
	return func(e events.Event) bool {
		if e.Agent != "" {
			return e.Agent == agent
		}
		if e.ResourceKind == "" {
			return false
		}
		d := eng.Policy().Decide(agent, e.ResourceKind+".read", e.ResourceKind, e.Resource)
		return d.Action == policy.Allow
	}
}

// serveEvents streams events as Server-Sent Events. Clients resume with the
// Last-Event-ID header (or ?since=ID) and may filter with ?types=a,b.
func serveEvents(bus *events.Bus, allow func(events.Event) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bus == nil {
			writeError(w, core.Errorf(core.CodeProviderUnavailable, "events are disabled"))
			return
		}
		cursor := r.Header.Get("Last-Event-ID")
		if cursor == "" {
			cursor = r.URL.Query().Get("since")
		}
		var after int64
		if cursor != "" {
			n, err := strconv.ParseInt(cursor, 10, 64)
			if err != nil || n < 0 {
				writeError(w, core.Errorf(core.CodeInvalidArgument, "invalid event cursor %q", cursor))
				return
			}
			after = n
		}
		types := map[string]bool{}
		for _, t := range strings.Split(r.URL.Query().Get("types"), ",") {
			if t = strings.TrimSpace(t); t != "" {
				types[t] = true
			}
		}
		replay, ch, cancel := bus.Subscribe(after, func(e events.Event) bool {
			return (len(types) == 0 || types[e.Type]) && allow(e)
		})
		defer cancel()

		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{})
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		send := func(e events.Event) error {
			b, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.Type, b); err != nil {
				return err
			}
			return rc.Flush()
		}
		for _, e := range replay {
			if send(e) != nil {
				return
			}
		}
		if rc.Flush() != nil {
			return
		}
		tick := time.NewTicker(keepalive)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case e := <-ch:
				if send(e) != nil {
					return
				}
			case <-tick.C:
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil || rc.Flush() != nil {
					return
				}
			}
		}
	}
}

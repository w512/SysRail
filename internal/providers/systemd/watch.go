package systemd

import (
	"context"
	"strings"
	"time"

	"github.com/w512/SysRail/internal/core/events"
)

const defaultWatchInterval = 5 * time.Second

// Watch polls service states and publishes service.failed when a service
// enters the failed state and service.recovered when it becomes active again.
// The first poll only establishes a baseline.
func (p *Provider) Watch(ctx context.Context, publish func(events.Event)) {
	interval := p.opts.WatchInterval
	if interval <= 0 {
		interval = defaultWatchInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var prev map[string]UnitStatus
	for {
		if units, err := p.opts.Manager.ListUnits(ctx, nil, []string{"*.service"}); err == nil {
			cur := make(map[string]UnitStatus, len(units))
			for _, u := range units {
				if strings.HasSuffix(u.Name, ".service") {
					cur[u.Name] = u
				}
			}
			if prev != nil {
				for name, u := range cur {
					old := prev[name].ActiveState
					var typ string
					switch {
					case u.ActiveState == "failed" && old != "failed":
						typ = events.ServiceFailed
					case old == "failed" && u.ActiveState == "active":
						typ = events.ServiceRecovered
					default:
						continue
					}
					publish(events.Event{
						Type: typ, Source: "systemd", ResourceKind: "service", Resource: name,
						Data: map[string]any{"previous_state": old, "active_state": u.ActiveState, "sub_state": u.SubState},
					})
				}
			}
			prev = cur
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

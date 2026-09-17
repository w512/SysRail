package linux

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/w512/SysRail/internal/core"
)

func conns(m map[string]any) []map[string]any {
	var out []map[string]any
	for _, c := range m["connections"].([]any) {
		out = append(out, c.(map[string]any))
	}
	return out
}

func TestConnectionsListening(t *testing.T) {
	m := call(t, testProvider(t, Options{}), "network_get_connections", `{}`)
	cs := conns(m)
	if len(cs) != 4 || m["truncated"] != false {
		t.Fatalf("listening sockets: %v", cs)
	}
	want := []struct {
		proto, addr string
		port        float64
	}{{"tcp", "0.0.0.0", 22}, {"tcp", "127.0.0.1", 8080}, {"tcp6", "::", 22}, {"udp", "127.0.0.53", 53}}
	for i, w := range want {
		if cs[i]["protocol"] != w.proto || cs[i]["local_address"] != w.addr || cs[i]["local_port"] != w.port ||
			cs[i]["state"] != "listen" || cs[i]["remote_address"] != nil {
			t.Fatalf("entry %d: %v, want %+v", i, cs[i], w)
		}
	}
	if cs[1]["uid"] != 1000.0 {
		t.Fatalf("uid: %v", cs[1])
	}
}

func TestConnectionsFilters(t *testing.T) {
	p := testProvider(t, Options{})
	est := conns(call(t, p, "network_get_connections", `{"state":"established"}`))
	if len(est) != 1 || est[0]["remote_address"] != "198.51.100.7" || est[0]["remote_port"] != 51234.0 ||
		est[0]["local_address"] != "192.0.2.10" {
		t.Fatalf("established: %v", est)
	}
	if udp := conns(call(t, p, "network_get_connections", `{"protocol":"udp"}`)); len(udp) != 1 {
		t.Fatalf("udp: %v", udp)
	}
	if byPort := conns(call(t, p, "network_get_connections", `{"state":"all","port":22}`)); len(byPort) != 3 {
		t.Fatalf("port 22: %v", byPort)
	}
	m := call(t, p, "network_get_connections", `{"state":"all","limit":2}`)
	if len(conns(m)) != 2 || m["truncated"] != true || m["total"] != 5.0 {
		t.Fatalf("limit: %v", m)
	}
}

func TestConnectionsRejectsBadArgs(t *testing.T) {
	p := testProvider(t, Options{})
	for _, c := range p.Capabilities() {
		if c.Tool != "network_get_connections" {
			continue
		}
		for _, args := range []string{`{"state":"weird"}`, `{"port":70000}`, `{"limit":0}`, `{"protocol":"sctp"}`} {
			_, err := c.Bind(json.RawMessage(args))
			if e := core.AsError(err); e == nil || e.Code != core.CodeInvalidArgument {
				t.Errorf("%s: got %v", args, err)
			}
		}
		inv, _ := c.Bind(json.RawMessage(`{}`))
		if string(inv.Args) != `{"state":"listen","protocol":"all","limit":200}` {
			t.Errorf("defaults not normalized: %s", inv.Args)
		}
		if _, err := inv.Run(context.Background()); err != nil {
			t.Error(err)
		}
	}
}

func TestParseHexEndpoint(t *testing.T) {
	addr, port, err := parseHexEndpoint("B80D01200000000000000000FF000000:01BB")
	if err != nil || addr.String() != "2001:db8::ff" || port != 443 {
		t.Fatalf("%v %d %v", addr, port, err)
	}
	for _, bad := range []string{"nocolon", "0100007F:ZZZZ", "01:0016"} {
		if _, _, err := parseHexEndpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

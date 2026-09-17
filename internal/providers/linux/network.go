package linux

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/w512/SysRail/internal/core"
)

var tcpStates = map[string]string{
	"01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1", "05": "fin_wait2",
	"06": "time_wait", "07": "close", "08": "close_wait", "09": "last_ack", "0A": "listen", "0B": "closing",
}

type connArgs struct {
	State    string `json:"state,omitempty" jsonschema:"listen (default; includes bound UDP sockets), established or all"`
	Protocol string `json:"protocol,omitempty" jsonschema:"tcp, udp or all (default)"`
	Port     int    `json:"port,omitempty" jsonschema:"Only sockets whose local or remote port matches"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Maximum entries to return (default 200)"`
}

func connSchema() *jsonschema.Schema {
	return core.SchemaFor[connArgs](func(p map[string]*jsonschema.Schema) {
		p["state"].Enum = []any{"listen", "established", "all"}
		p["protocol"].Enum = []any{"tcp", "udp", "all"}
		p["port"].Minimum, p["port"].Maximum = core.Ptr(1.0), core.Ptr(65535.0)
		p["limit"].Minimum, p["limit"].Maximum = core.Ptr(1.0), core.Ptr(2000.0)
	})
}

func validateConnArgs(in *connArgs) (string, error) {
	if in.State == "" {
		in.State = "listen"
	}
	if in.Protocol == "" {
		in.Protocol = "all"
	}
	if in.Limit == 0 {
		in.Limit = 200
	}
	return "", nil
}

type conn struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`
	State         string `json:"state"`
	UID           int    `json:"uid"`
}

type connList struct {
	Connections []conn `json:"connections"`
	Total       int    `json:"total"`
	Truncated   bool   `json:"truncated"`
}

func (p *Provider) connections(in connArgs) (any, error) {
	var tables []string
	if in.Protocol != "udp" {
		tables = append(tables, "tcp", "tcp6")
	}
	if in.Protocol != "tcp" {
		tables = append(tables, "udp", "udp6")
	}
	var all []conn
	read := 0
	for _, proto := range tables {
		b, err := readFile(p.opts.Root, "proc/net/"+proto)
		if errors.Is(err, fs.ErrNotExist) {
			continue // e.g. IPv6 disabled
		}
		if err != nil {
			return nil, unavailable("/proc/net/"+proto, err)
		}
		read++
		conns, err := parseNetTable(proto, b)
		if err != nil {
			return nil, unavailable("/proc/net/"+proto, err)
		}
		for _, c := range conns {
			if matchesConn(c, in) {
				all = append(all, c)
			}
		}
	}
	if read == 0 {
		return nil, unavailable("socket tables", fs.ErrNotExist)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Protocol != all[j].Protocol {
			return all[i].Protocol < all[j].Protocol
		}
		if all[i].LocalPort != all[j].LocalPort {
			return all[i].LocalPort < all[j].LocalPort
		}
		return all[i].LocalAddress < all[j].LocalAddress
	})
	out := connList{Connections: all, Total: len(all)}
	if out.Connections == nil {
		out.Connections = []conn{}
	}
	if len(all) > in.Limit {
		out.Connections, out.Truncated = all[:in.Limit], true
	}
	return out, nil
}

func matchesConn(c conn, in connArgs) bool {
	switch in.State {
	case "listen":
		if c.State != "listen" {
			return false
		}
	case "established":
		if c.State != "established" {
			return false
		}
	}
	return in.Port == 0 || c.LocalPort == in.Port || c.RemotePort == in.Port
}

// parseNetTable parses /proc/net/{tcp,tcp6,udp,udp6}.
func parseNetTable(proto string, data []byte) ([]conn, error) {
	var out []conn
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		la, lp, err := parseHexEndpoint(f[1])
		if err != nil {
			return nil, err
		}
		ra, rp, err := parseHexEndpoint(f[2])
		if err != nil {
			return nil, err
		}
		state := tcpStates[f[3]]
		if strings.HasPrefix(proto, "udp") {
			// Unconnected bound UDP sockets report TCP_CLOSE.
			state = map[string]string{"07": "listen", "01": "established"}[f[3]]
		}
		if state == "" {
			state = "unknown"
		}
		uid, _ := strconv.Atoi(f[7])
		c := conn{Protocol: proto, LocalAddress: la.String(), LocalPort: lp, State: state, UID: uid}
		if rp != 0 || !ra.IsUnspecified() {
			c.RemoteAddress, c.RemotePort = ra.String(), rp
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

// parseHexEndpoint decodes "0100007F:1F90" (address words in host
// little-endian order, port big-endian).
func parseHexEndpoint(s string) (netip.Addr, int, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("malformed endpoint %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("malformed port %q", s)
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("malformed address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	addr, _ := netip.AddrFromSlice(raw)
	return addr, int(port), nil
}

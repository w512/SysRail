package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/w512/SysRail/internal/api/httpapi"
	"github.com/w512/SysRail/internal/client"
	"github.com/w512/SysRail/internal/core/request"
)

const defaultAdminSocket = "/run/sysrail/admin.sock"

// stdin is replaceable in tests.
var stdin io.Reader = os.Stdin

func adminClient(socket string) (*client.Client, error) {
	c, err := client.New(socket, "")
	if err != nil {
		return nil, err
	}
	actor := os.Getenv("SUDO_USER")
	if actor == "" {
		actor = os.Getenv("USER")
	}
	if actor != "" {
		c.SetHeader(httpapi.ActorHeader, actor)
	}
	return c, nil
}

func adminFlags(name string, stderr io.Writer) (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	def := os.Getenv("SYSRAIL_ADMIN_SOCKET")
	if def == "" {
		def = defaultAdminSocket
	}
	socket := fs.String("socket", def, "admin socket path (env SYSRAIL_ADMIN_SOCKET)")
	asJSON := fs.Bool("json", false, "print JSON")
	return fs, socket, asJSON
}

func runApprovals(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "Usage: sysrail approvals list [--all] | show ID | approve ID [--note TEXT] [--yes] | deny ID [--note TEXT]")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	sub, rest := args[0], args[1:]
	fs, socket, asJSON := adminFlags("approvals "+sub, stderr)
	all := fs.Bool("all", false, "list requests in every state (list)")
	note := fs.String("note", "", "note recorded with the decision (approve, deny)")
	yes := fs.Bool("yes", false, "approve without asking for confirmation (approve)")
	var id string
	if sub != "list" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return usage()
		}
		id, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	c, err := adminClient(*socket)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	ctx := context.Background()
	fail := func(err error) int {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}

	switch sub {
	case "list":
		q := url.Values{}
		if !*all {
			q.Set("status", string(request.Pending))
		}
		var out struct {
			Requests []request.Request `json:"requests"`
		}
		if _, err := c.Do(ctx, http.MethodGet, "/v1/requests?"+q.Encode(), nil, &out); err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(stdout, out.Requests)
		}
		if len(out.Requests) == 0 {
			fmt.Fprintln(stdout, "no pending requests")
			return 0
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tAGENT\tCAPABILITY\tRESOURCE\tRISK\tSTATUS\tCREATED\tEXPIRES")
		for _, r := range out.Requests {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Agent, r.Capability, dash(r.Resource),
				r.Risk, r.Status, ago(r.CreatedAt), until(r.ExpiresAt, r.Status))
		}
		tw.Flush()
		return 0

	case "show":
		r, err := getRequest(ctx, c, id)
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(stdout, r)
		}
		printRequest(stdout, r, impactOf(ctx, c, r.Capability))
		return 0

	case "approve":
		r, err := getRequest(ctx, c, id)
		if err != nil {
			return fail(err)
		}
		if !*yes {
			printRequest(stdout, r, impactOf(ctx, c, r.Capability))
			fmt.Fprint(stdout, "\nApprove and execute this request? [y/N] ")
			answer, _ := bufio.NewReader(stdin).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
				fmt.Fprintln(stdout, "not approved")
				return 1
			}
		}
		return decide(ctx, c, id, "approve", *note, *asJSON, stdout, stderr)

	case "deny":
		return decide(ctx, c, id, "deny", *note, *asJSON, stdout, stderr)
	}
	return usage()
}

func getRequest(ctx context.Context, c *client.Client, id string) (*request.Request, error) {
	var r request.Request
	if _, err := c.Do(ctx, http.MethodGet, "/v1/requests/"+url.PathEscape(id), nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func impactOf(ctx context.Context, c *client.Client, capability string) string {
	var out struct {
		Capabilities []httpapi.CapabilityInfo `json:"capabilities"`
	}
	if _, err := c.Do(ctx, http.MethodGet, "/v1/capabilities", nil, &out); err != nil {
		return ""
	}
	for _, ci := range out.Capabilities {
		if ci.ID == capability {
			return ci.Impact
		}
	}
	return ""
}

func decide(ctx context.Context, c *client.Client, id, verb, note string, asJSON bool, stdout, stderr io.Writer) int {
	var r request.Request
	if _, err := c.Do(ctx, http.MethodPost, "/v1/requests/"+url.PathEscape(id)+"/"+verb,
		httpapi.DecisionRequest{Note: note}, &r); err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	if asJSON {
		return printJSON(stdout, r)
	}
	fmt.Fprintf(stdout, "%s: %s\n", r.ID, r.Status)
	if r.Error != nil {
		fmt.Fprintf(stdout, "error: %s: %s\n", r.Error.Code, r.Error.Message)
		return 1
	}
	if len(r.Result) > 0 {
		fmt.Fprintf(stdout, "result: %s\n", r.Result)
	}
	return 0
}

func printRequest(w io.Writer, r *request.Request, impact string) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Request:\t%s\n", r.ID)
	fmt.Fprintf(tw, "Status:\t%s\n", r.Status)
	fmt.Fprintf(tw, "Agent:\t%s\n", r.Agent)
	fmt.Fprintf(tw, "Capability:\t%s (risk: %s)\n", r.Capability, r.Risk)
	fmt.Fprintf(tw, "Resource:\t%s\n", dash(r.Resource))
	fmt.Fprintf(tw, "Arguments:\t%s\n", r.Args)
	if impact != "" {
		fmt.Fprintf(tw, "Impact:\t%s\n", impact)
	}
	fmt.Fprintf(tw, "Reason:\t%s\n", reasonLine(r.Reason))
	fmt.Fprintf(tw, "Policy:\t%s\n", dash(r.PolicyRule))
	fmt.Fprintf(tw, "Created:\t%s (%s)\n", r.CreatedAt.Local().Format(time.DateTime), ago(r.CreatedAt))
	if r.ExpiresAt != nil {
		fmt.Fprintf(tw, "Expires:\t%s (%s)\n", r.ExpiresAt.Local().Format(time.DateTime), until(r.ExpiresAt, r.Status))
	}
	if r.DecidedBy != "" {
		fmt.Fprintf(tw, "Decided by:\t%s\n", r.DecidedBy)
	}
	if r.DecisionNote != "" {
		fmt.Fprintf(tw, "Note:\t%s\n", r.DecisionNote)
	}
	if r.Error != nil {
		fmt.Fprintf(tw, "Error:\t%s: %s\n", r.Error.Code, r.Error.Message)
	}
	if len(r.Result) > 0 {
		fmt.Fprintf(tw, "Result:\t%s\n", r.Result)
	}
	tw.Flush()
}

// reasonLine marks the agent-supplied reason as untrusted and strips control
// characters so it cannot rewrite the terminal.
func reasonLine(s string) string {
	if s == "" {
		return "-"
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return fmt.Sprintf("%q (from the agent, unverified)", clean)
}

func printJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func ago(t time.Time) string {
	return time.Since(t).Round(time.Second).String() + " ago"
}

func until(t *time.Time, status request.Status) string {
	if t == nil || status != request.Pending {
		return "-"
	}
	d := time.Until(*t).Round(time.Second)
	if d <= 0 {
		return "expired"
	}
	return "in " + d.String()
}

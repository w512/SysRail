// Command sysrail is a permissioned control plane for AI agents on Linux.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/w512/SysRail/internal/version"
)

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

func commands() []command {
	return []command{
		{"serve", "run the daemon", runServe},
		{"mcp", "serve MCP over stdio for an agent (proxies to the daemon)", runMCP},
		{"approvals", "list, show, approve or deny pending requests", runApprovals},
		{"audit", "show the audit log", runAudit},
		{"token", "create an agent token", runToken},
		{"notify", "send a test message to every notification channel", runNotify},
		{"policy", "validate the policy and show effective grants", runPolicy},
		{"version", "print version", runVersion},
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "sysrail: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: sysrail <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
}

func runVersion(_ []string, stdout, _ io.Writer) int {
	fmt.Fprintf(stdout, "sysrail %s\n", version.Version)
	return 0
}

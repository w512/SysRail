package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/w512/SysRail/internal/api/httpapi"
	"github.com/w512/SysRail/internal/api/mcpshim"
	"github.com/w512/SysRail/internal/client"
	"github.com/w512/SysRail/internal/core"
)

const defaultAgentURL = "unix:///run/sysrail/agent.sock"

// runMCP serves MCP over stdio. stdout carries the protocol, so diagnostics
// go to stderr only.
func runMCP(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", envOr("SYSRAIL_URL", defaultAgentURL), "daemon agent API: unix:///path or http://host:port (env SYSRAIL_URL)")
	tokenFile := fs.String("token-file", os.Getenv("SYSRAIL_TOKEN_FILE"), "file containing the agent token (env SYSRAIL_TOKEN_FILE)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	token := os.Getenv("SYSRAIL_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(stderr, "sysrail mcp:", err)
			return 1
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		fmt.Fprintln(stderr, "sysrail mcp: no agent token; set SYSRAIL_TOKEN or --token-file")
		return 1
	}
	c, err := client.New(*url, token)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail mcp:", err)
		return 1
	}
	c.SetHeader(httpapi.SessionHeader, core.NewID("sess"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.Wait(ctx, 5*time.Second); err != nil {
		fmt.Fprintf(stderr, "sysrail mcp: daemon at %s is not reachable: %v\n", *url, err)
		return 1
	}
	server, err := mcpshim.New(ctx, c)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail mcp:", err)
		return 1
	}
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(stderr, "sysrail mcp:", err)
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

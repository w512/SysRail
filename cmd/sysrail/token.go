package main

import (
	"fmt"
	"io"

	"github.com/w512/SysRail/internal/auth"
)

func runToken(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "create" {
		fmt.Fprintln(stderr, "Usage: sysrail token create")
		return 2
	}
	tok, hash, err := auth.NewToken()
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	fmt.Fprintf(stdout, "token:        %s\ntoken_sha256: %s\n\n", tok, hash)
	fmt.Fprintln(stdout, "Give the token to the agent (e.g. SYSRAIL_TOKEN) and put token_sha256")
	fmt.Fprintln(stdout, "under agents.<name> in the config. The token is not stored anywhere.")
	return 0
}

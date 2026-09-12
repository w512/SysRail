//go:build !linux

package server

import "net"

func peerUID(*net.UnixConn) (uint32, bool) { return 0, false }

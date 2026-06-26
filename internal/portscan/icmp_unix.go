//go:build linux || darwin || freebsd

package portscan

import (
	"net"
	"time"
)

// newICMPListener opens a raw ICMP socket to capture port-unreachable
// messages for UDP scan correlation. Returns nil if unavailable (no root) —
// callers must treat that as "ICMP correlation off", not an error.
func newICMPListener(target string) *icmpListener {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil // no root — fall back to silence-only UDP classification
	}
	return &icmpListener{
		seen: make(map[icmpUnreachableKey]time.Time),
		conn: conn,
	}
}

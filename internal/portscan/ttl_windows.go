//go:build windows

package portscan

import "time"

// dialAndMeasure is not implemented on Windows: Go's net package does not
// expose IP_TTL via a portable SyscallConn path the way Unix does, and
// raw-socket TTL extraction requires Administrator + WinSock IOCTL access
// beyond this build's scope. Returns ok=false so callers report OS detection
// as unavailable rather than guessing.
func dialAndMeasure(target string, port int, timeout time.Duration) (ttl, windowSize int, ok bool) {
	return 0, 0, false
}

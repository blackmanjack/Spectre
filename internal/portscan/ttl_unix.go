//go:build linux || darwin || freebsd

package portscan

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// readTTL extracts the IP_TTL socket option from an established TCP connection.
// Only works on platforms with raw socket / sockopt access (requires the
// underlying fd, which net.TCPConn exposes via SyscallConn on Unix).
func readTTL(conn *net.TCPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ttl int
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		ttl, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	})
	if err != nil {
		return 0, err
	}
	return ttl, sockErr
}

// dialAndMeasure connects to target:port and reads the negotiated TTL + window size.
// Returns (0, 0, false) if measurement is unavailable on this platform/connection.
func dialAndMeasure(target string, port int, timeout time.Duration) (ttl, windowSize int, ok bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(target, itoa(port)))
	if err != nil {
		return 0, 0, false
	}
	defer conn.Close()

	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return 0, 0, false
	}
	t, err := readTTL(tcpConn)
	if err != nil || t == 0 {
		return 0, 0, false
	}
	// Window size is not exposed via standard sockopts in a portable way;
	// TTL alone is still a useful (if weaker) OS fingerprint signal.
	return t, 0, true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

package portscan

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// grabBanner connects to target:port, optionally sends a probe, and reads up to 512 bytes.
func grabBanner(ctx context.Context, target string, port int, send string, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if send != "" {
		if _, err := conn.Write([]byte(send)); err != nil {
			return nil, err
		}
	}

	buf := make([]byte, 512)
	n, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// serviceDetect performs banner grabbing and service fingerprinting for a port.
// Returns (service, version, banner, confidence).
func serviceDetect(ctx context.Context, target string, port int, db *ProbeDB, timeout time.Duration) (string, string, string, int) {
	probes := db.ProbesFor(port)
	if len(probes) == 0 {
		// Use NULL probe as fallback
		probes = []ServiceProbe{{Name: "NULL", Protocol: "TCP", Send: ""}}
	}

	for _, p := range probes {
		banner, err := grabBanner(ctx, target, port, p.Send, timeout)
		if err != nil || len(banner) == 0 {
			continue
		}
		svc, ver, conf := db.Match(banner)
		if svc != "" {
			return svc, ver, truncate(string(banner), 512), conf
		}
		// Return raw banner even without match
		return guessServiceByPort(port), "", truncate(string(banner), 512), 30
	}
	// No banner — guess by port number only
	return guessServiceByPort(port), "", "", 20
}

// guessServiceByPort returns a best-guess service name from well-known port numbers.
func guessServiceByPort(port int) string {
	wellKnown := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
		135: "msrpc", 139: "netbios-ssn", 143: "imap",
		443: "https", 445: "microsoft-ds", 587: "submission",
		993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
		1521: "oracle", 3306: "mysql", 3389: "ms-wbt-server",
		5432: "postgresql", 5900: "vnc", 6379: "redis",
		8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
		9200: "elasticsearch", 11211: "memcache", 2375: "docker",
	}
	if svc, ok := wellKnown[port]; ok {
		return svc
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

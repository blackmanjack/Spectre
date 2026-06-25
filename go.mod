module github.com/spectre-tool/spectre

go 1.22

require (
	// CLI framework — CNCF, ubiquitous, audited
	github.com/spf13/cobra v1.8.0
	// Official Go rate limiter (token bucket)
	golang.org/x/time v0.5.0
	// Official Go networking: dnsmessage + SOCKS5 proxy
	golang.org/x/net v0.22.0
	// Official Go syscall layer: raw sockets (SYN/FIN/ACK scan)
	golang.org/x/sys v0.18.0
)

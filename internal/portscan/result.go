package portscan

import "time"

// PortState represents the determined state of a port.
type PortState int

const (
	StateUnknown      PortState = iota
	StateOpen                   // SYN-ACK confirmed
	StateClosed                 // RST confirmed
	StateFiltered               // no response after all probes + retries
	StateOpenFiltered           // open but firewall prevents confirmation
	StateUnfiltered             // ACK probe returned RST (firewall mapping)
)

func (s PortState) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateFiltered:
		return "filtered"
	case StateOpenFiltered:
		return "open|filtered"
	case StateUnfiltered:
		return "unfiltered"
	default:
		return "unknown"
	}
}

// PortResult holds the full scan result for one port.
type PortResult struct {
	Port       int
	Protocol   string    // tcp|udp
	State      PortState
	Service    string    // http, ssh, ftp, etc.
	Version    string    // OpenSSH 7.4, nginx/1.18, etc.
	Banner     string    // raw banner first 512 bytes
	Confidence int       // 0-100 for service/version detection
	ProbeUsed  string    // which probe confirmed the state
	TTL        int       // from response packet
	OS         string    // OS guess from this port's response
	Timestamp  time.Time
}

// ScanSummary holds statistics for a complete scan.
type ScanSummary struct {
	Target    string
	OpenPorts []PortResult
	OS        OSResult
	StartTime time.Time
	Duration  string
	Total     int // total ports probed
}

// OSResult holds OS fingerprint findings.
type OSResult struct {
	Name       string
	Confidence int
	TTL        int
	WindowSize int
	TCPOptions string
	Method     string // "passive" or "active"
}

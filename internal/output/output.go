package output

import (
	"io"
	"time"
)

// ResultType identifies which module produced the result.
type ResultType string

const (
	TypeSubdomain ResultType = "subdomain"
	TypeDirFuzz   ResultType = "dirfuzz"
	TypePort      ResultType = "port"
	TypeDNS       ResultType = "dns"
	TypeWebTech   ResultType = "webtech"
)

// Result is the unified result type for all modules.
type Result struct {
	Type      ResultType `json:"type"`
	Value     string     `json:"value"`               // subdomain FQDN, path, host:port, record, tech name
	Source    string     `json:"source,omitempty"`    // crtsh, brute, raft-medium, etc.
	IPs       []string   `json:"ips,omitempty"`       // resolved IPs
	Status    int        `json:"status,omitempty"`    // HTTP status (dirfuzz/webtech)
	Size      int64      `json:"size,omitempty"`      // response size bytes
	Words     int        `json:"words,omitempty"`     // word count in response
	Lines     int        `json:"lines,omitempty"`     // line count in response
	Port      int        `json:"port,omitempty"`      // port number (portscan)
	Protocol  string     `json:"protocol,omitempty"`  // tcp/udp
	State     string     `json:"state,omitempty"`     // open/closed/filtered/open|filtered
	Service   string     `json:"service,omitempty"`   // http, ssh, etc.
	Version   string     `json:"version,omitempty"`   // service version
	Banner    string     `json:"banner,omitempty"`    // raw banner (first 512 bytes)
	OS        string     `json:"os,omitempty"`        // OS detection result
	Confidence int       `json:"confidence,omitempty"` // 0-100
	Extra     string     `json:"extra,omitempty"`     // additional info
	Timestamp time.Time  `json:"timestamp"`
}

// Writer is the output abstraction implemented by text and JSON writers.
type Writer interface {
	Write(r Result) error
	Flush() error
	Close() error
}

// NewWriter constructs a Writer based on format string ("text" or "json").
func NewWriter(format string, dest io.Writer, noColor bool) Writer {
	switch format {
	case "json", "jsonl", "ndjson":
		return NewJSONWriter(dest)
	default:
		return NewTextWriter(dest, noColor)
	}
}

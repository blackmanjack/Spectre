package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Audit writes an append-only JSONL record of every scan invocation.
// Default path: ~/.spectre/audit.jsonl
type Audit struct {
	mu sync.Mutex
	f  *os.File
}

type auditEntry struct {
	Timestamp string         `json:"timestamp"`
	Command   string         `json:"command"`
	Target    string         `json:"target"`
	Flags     map[string]any `json:"flags,omitempty"`
	Operator  string         `json:"operator"`
	ScopeFile string         `json:"scope_file,omitempty"`
	PID       int            `json:"pid"`
}

// NewAudit opens (or creates) the audit log at path.
// If path is "", uses ~/.spectre/audit.jsonl.
func NewAudit(path string) (*Audit, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(home, ".spectre")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		path = filepath.Join(dir, "audit.jsonl")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Audit{f: f}, nil
}

// Log writes one audit record. Safe for concurrent use.
func (a *Audit) Log(command, target, scopeFile string, flags map[string]any) error {
	if a == nil {
		return nil
	}
	entry := auditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Command:   command,
		Target:    target,
		Flags:     flags,
		Operator:  currentUser(),
		ScopeFile: scopeFile,
		PID:       os.Getpid(),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = fmt.Fprintf(a.f, "%s\n", line)
	return err
}

// Close closes the audit log file.
func (a *Audit) Close() {
	if a != nil && a.f != nil {
		_ = a.f.Close()
	}
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

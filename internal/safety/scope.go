package safety

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Scope enforces an allowlist of authorized targets.
// Every scan command must call Authorized() before sending any packet.
type Scope struct {
	cidrs     []*net.IPNet
	hosts     map[string]bool
	wildcards []string
}

// LoadScope reads a scope file (one entry per line).
// Supported formats: CIDR (1.2.3.0/24), IP, hostname, wildcard (*.example.com).
func LoadScope(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := &Scope{hosts: make(map[string]bool)}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			_, cidr, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", line, err)
			}
			s.cidrs = append(s.cidrs, cidr)
		} else if strings.HasPrefix(line, "*.") {
			s.wildcards = append(s.wildcards, strings.TrimPrefix(line, "*."))
		} else {
			s.hosts[strings.ToLower(line)] = true
		}
	}
	return s, scanner.Err()
}

// Authorized returns (true, "") if the target is in scope,
// or (false, reason) if it is out of scope.
// If scope is nil (no --scope flag), all targets are allowed with a warning.
func (s *Scope) Authorized(target string) (bool, string) {
	if s == nil {
		return true, ""
	}
	lower := strings.ToLower(strings.TrimSpace(target))

	// Check IP
	if ip := net.ParseIP(lower); ip != nil {
		for _, cidr := range s.cidrs {
			if cidr.Contains(ip) {
				return true, ""
			}
		}
		if s.hosts[lower] {
			return true, ""
		}
		return false, fmt.Sprintf("IP %s is not in scope", target)
	}

	// Check hostname/domain
	if s.hosts[lower] {
		return true, ""
	}
	for _, wc := range s.wildcards {
		if lower == wc || strings.HasSuffix(lower, "."+wc) {
			return true, ""
		}
	}
	// Try resolving and checking IPs
	ips, err := net.LookupHost(lower)
	if err == nil {
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			for _, cidr := range s.cidrs {
				if cidr.Contains(ip) {
					return true, ""
				}
			}
		}
	}
	return false, fmt.Sprintf("host %s is not in scope", target)
}

package subdomain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"github.com/spectre-tool/spectre/internal/utils"
)

// WildcardDetector determines whether a domain has wildcard DNS configured.
// This prevents false positives from flooding brute-force results.
type WildcardDetector struct {
	pool *utils.ResolverPool
}

// WildcardResult holds detection outcome.
type WildcardResult struct {
	IsWildcard  bool
	WildcardIPs []net.IP
	WildcardMap map[string]bool // O(1) lookup by ip.String()
}

// NewWildcardDetector creates a detector using the given resolver pool.
func NewWildcardDetector(pool *utils.ResolverPool) *WildcardDetector {
	return &WildcardDetector{pool: pool}
}

// Detect probes domain with 3 random labels to determine wildcard DNS.
// If all 3 resolve, wildcard is confirmed and the union of IPs is returned.
// These IPs are then used during brute force to discard wildcard matches.
func (w *WildcardDetector) Detect(ctx context.Context, domain string) (*WildcardResult, error) {
	probes := make([]string, 3)
	for i := range probes {
		label, err := randomLabel()
		if err != nil {
			return nil, err
		}
		probes[i] = label + "." + domain
	}

	var allIPs []net.IP
	resolved := 0
	for _, probe := range probes {
		ips, err := w.pool.Resolve(ctx, probe)
		if err != nil || len(ips) == 0 {
			// NXDOMAIN or error — this probe didn't resolve, no wildcard for this probe
			continue
		}
		resolved++
		allIPs = append(allIPs, ips...)
	}

	// Require ALL 3 probes to resolve before declaring wildcard
	// This avoids false positives from transient DNS responses
	if resolved < 3 {
		return &WildcardResult{IsWildcard: false}, nil
	}

	// Deduplicate wildcard IPs
	seen := make(map[string]bool)
	var unique []net.IP
	for _, ip := range allIPs {
		k := ip.String()
		if !seen[k] {
			seen[k] = true
			unique = append(unique, ip)
		}
	}

	fmt.Fprintf(os.Stderr, "[WARN] Wildcard DNS detected: *.%s -> %s\n", domain, utils.FormatIPList(unique))

	return &WildcardResult{
		IsWildcard:  true,
		WildcardIPs: unique,
		WildcardMap: seen,
	}, nil
}

// IsWildcardMatch returns true if ALL resolved IPs are wildcard IPs.
// If any IP is novel (not in wildcard set), this is a real subdomain.
func (r *WildcardResult) IsWildcardMatch(ips []net.IP) bool {
	if !r.IsWildcard || len(r.WildcardMap) == 0 {
		return false
	}
	for _, ip := range ips {
		if !r.WildcardMap[ip.String()] {
			return false // novel IP — real subdomain
		}
	}
	return true
}

func randomLabel() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

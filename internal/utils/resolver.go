package utils

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// ResolverPool distributes DNS queries round-robin across a set of resolvers.
// Uses net.Resolver with custom Dial to bypass OS DNS cache (critical on Windows).
type ResolverPool struct {
	resolvers []string
	mu        sync.Mutex
	idx       int
	errors    []int64 // per-resolver consecutive error count
}

// NewResolverPool creates a pool from "ip:port" strings.
// Defaults to well-known public DNS if empty.
func NewResolverPool(resolvers []string) *ResolverPool {
	if len(resolvers) == 0 {
		resolvers = []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"9.9.9.9:53",
			"8.8.4.4:53",
		}
	}
	p := &ResolverPool{
		resolvers: resolvers,
		errors:    make([]int64, len(resolvers)),
	}
	return p
}

// Resolve performs an A/AAAA lookup using the next healthy resolver.
// Returns (ips, nil) on success or (nil, err) on failure.
func (p *ResolverPool) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	idx := p.next()
	resolver := p.makeResolver(idx)
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		atomic.AddInt64(&p.errors[idx], 1)
		return nil, err
	}
	atomic.StoreInt64(&p.errors[idx], 0)
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// ResolveHost resolves to string IPs (convenience wrapper).
func (p *ResolverPool) ResolveHost(ctx context.Context, host string) ([]string, error) {
	ips, err := p.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out, nil
}

// LookupNS returns name servers for a domain.
func (p *ResolverPool) LookupNS(ctx context.Context, domain string) ([]*net.NS, error) {
	idx := p.next()
	resolver := p.makeResolver(idx)
	return resolver.LookupNS(ctx, domain)
}

// LookupMX returns MX records.
func (p *ResolverPool) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	idx := p.next()
	return p.makeResolver(idx).LookupMX(ctx, domain)
}

// LookupTXT returns TXT records.
func (p *ResolverPool) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	idx := p.next()
	return p.makeResolver(idx).LookupTXT(ctx, domain)
}

func (p *ResolverPool) next() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Skip resolvers with too many consecutive errors
	for i := 0; i < len(p.resolvers); i++ {
		idx := p.idx % len(p.resolvers)
		p.idx++
		if atomic.LoadInt64(&p.errors[idx]) < 5 {
			return idx
		}
	}
	// All resolvers failing — reset and try first
	for i := range p.errors {
		atomic.StoreInt64(&p.errors[i], 0)
	}
	return 0
}

func (p *ResolverPool) makeResolver(idx int) *net.Resolver {
	addr := p.resolvers[idx]
	return &net.Resolver{
		PreferGo: true, // bypass OS resolver (important on Windows for accurate NXDOMAIN)
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			conn, err := d.DialContext(ctx, "udp", addr)
			if err != nil {
				// Fallback to TCP for large responses
				conn, err = d.DialContext(ctx, "tcp", addr)
			}
			return conn, err
		},
	}
}

// Resolver returns the underlying resolver string at index (for display).
func (p *ResolverPool) ResolverAt(i int) string {
	if i < len(p.resolvers) {
		return p.resolvers[i]
	}
	return ""
}

// FormatIPList formats a slice of IPs as "[1.2.3.4, 5.6.7.8]".
func FormatIPList(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}
	s := "["
	for i, ip := range ips {
		if i > 0 {
			s += ", "
		}
		s += ip.String()
	}
	return s + "]"
}

// FormatStringIPList formats string IPs as "[1.2.3.4, 5.6.7.8]".
func FormatStringIPList(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	return fmt.Sprintf("[%s]", joinStrings(ips, ", "))
}

func joinStrings(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

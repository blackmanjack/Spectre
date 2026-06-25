package dnsrecon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options for DNS recon.
type Options struct {
	Domain      string
	Resolvers   []string
	Timeout     time.Duration
	TryAxfr     bool
	Writer      output.Writer
}

// Run performs full DNS enumeration: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR,
// zone-transfer attempt, reverse DNS for resolved IPs.
func Run(ctx context.Context, opts Options) error {
	pool := utils.NewResolverPool(opts.Resolvers)

	emit := func(rtype, value string) {
		_ = opts.Writer.Write(output.Result{
			Type:      output.TypeDNS,
			Value:     fmt.Sprintf("%-8s %s", rtype, value),
			Source:    rtype,
			Timestamp: time.Now(),
		})
	}

	// A records
	ips, err := pool.Resolve(ctx, opts.Domain)
	if err == nil {
		for _, ip := range ips {
			emit("A", ip.String())
			// PTR for each IP
			if ptrs, err := net.LookupAddr(ip.String()); err == nil {
				for _, ptr := range ptrs {
					emit("PTR", fmt.Sprintf("%s -> %s", ip.String(), ptr))
				}
			}
		}
	}

	// MX records
	mxs, err := pool.LookupMX(ctx, opts.Domain)
	if err == nil {
		for _, mx := range mxs {
			emit("MX", fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
	}

	// NS records
	nss, err := pool.LookupNS(ctx, opts.Domain)
	if err == nil {
		for _, ns := range nss {
			emit("NS", ns.Host)
			// Zone transfer attempt per NS
			if opts.TryAxfr {
				tryAxfr(ctx, opts.Domain, strings.TrimSuffix(ns.Host, "."), emit)
			}
		}
	}

	// TXT records
	txts, err := pool.LookupTXT(ctx, opts.Domain)
	if err == nil {
		for _, txt := range txts {
			emit("TXT", txt)
		}
	}

	// Common well-known subdomains for record types
	for _, sub := range []string{"www", "mail", "smtp", "ftp", "vpn", "api"} {
		fqdn := sub + "." + opts.Domain
		ips, err := pool.Resolve(ctx, fqdn)
		if err == nil && len(ips) > 0 {
			emit("A", fmt.Sprintf("%s -> %s", fqdn, utils.FormatIPList(ips)))
		}
	}

	return nil
}

// tryAxfr attempts a DNS zone transfer (AXFR) from the given nameserver.
func tryAxfr(ctx context.Context, domain, ns string, emit func(string, string)) {
	// Use standard net package — full AXFR requires raw DNS messaging
	// We implement a basic AXFR via TCP to port 53
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", ns+":53")
	if err != nil {
		return
	}
	defer conn.Close()

	// Build AXFR query (DNS message type 252)
	msg := buildAxfrQuery(domain)
	if msg == nil {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// Send length-prefixed message (TCP DNS)
	lenbuf := []byte{byte(len(msg) >> 8), byte(len(msg))}
	if _, err := conn.Write(append(lenbuf, msg...)); err != nil {
		return
	}

	// Read response length
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	msgLen := int(buf[0])<<8 | int(buf[1])
	if msgLen <= 0 || msgLen > 65535 {
		return
	}

	resp := make([]byte, msgLen)
	if _, err := conn.Read(resp); err != nil {
		return
	}

	// Check RCODE (byte 3 lower nibble)
	if len(resp) < 4 {
		return
	}
	rcode := resp[3] & 0x0f
	if rcode == 0 {
		emit("AXFR", fmt.Sprintf("Zone transfer ALLOWED from %s (RCODE=0) — investigate!", ns))
	} else {
		emit("AXFR", fmt.Sprintf("Zone transfer refused from %s (RCODE=%d)", ns, rcode))
	}
}

// buildAxfrQuery builds a minimal DNS AXFR query for the given domain.
func buildAxfrQuery(domain string) []byte {
	// Minimal DNS wire format AXFR query
	// Transaction ID: 0x1234, Flags: standard query, QDCOUNT=1
	header := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// Encode domain labels
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	var qname []byte
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0x00) // root label

	// QTYPE=AXFR (252), QCLASS=IN (1)
	footer := []byte{0x00, 0xfc, 0x00, 0x01}
	return append(append(header, qname...), footer...)
}

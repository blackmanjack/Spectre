package portscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// udpProbes holds a small set of protocol-specific payloads for the handful
// of UDP services that actually reply to an empty/generic probe. Most UDP
// services say nothing unless you speak their protocol, so probing with the
// right payload is what makes UDP scanning useful at all (vs. just "timeout
// or ICMP unreachable").
var udpProbes = map[int][]byte{
	53:  dnsProbePayload(),                  // DNS: standard query for "."
	123: ntpProbePayload(),                  // NTP: client request (mode 3)
	161: snmpProbePayload(),                 // SNMP: GetRequest community "public"
	137: nil,                                // NetBIOS — name query, left as generic probe
}

// dnsProbePayload builds a minimal DNS query for the root domain, type A.
func dnsProbePayload() []byte {
	return []byte{
		0x12, 0x34, // transaction ID
		0x01, 0x00, // standard query
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QDCOUNT=1
		0x00,       // root label
		0x00, 0x01, // QTYPE=A
		0x00, 0x01, // QCLASS=IN
	}
}

// ntpProbePayload builds a minimal NTP client request (mode 3, version 3).
func ntpProbePayload() []byte {
	buf := make([]byte, 48)
	buf[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	return buf
}

// snmpProbePayload builds a minimal SNMPv1 GetRequest for sysDescr with
// community string "public" — the de facto default that's still worth trying.
func snmpProbePayload() []byte {
	// Pre-built minimal SNMPv1 GetRequest packet (community "public",
	// requesting 1.3.6.1.2.1.1.1.0 / sysDescr).
	return []byte{
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
		0x01, 0x00, 0x05, 0x00,
	}
}

// UDPResult mirrors PortResult for UDP-specific findings.
type UDPResult struct {
	Port    int
	State   PortState
	Banner  string
}

// scanUDPPorts probes each port with a protocol-specific (or generic) UDP
// payload and classifies the result honestly:
//
//   - response received                  -> StateOpen
//   - ICMP port-unreachable correlated    -> StateClosed   (Unix + root only)
//   - no response, no ICMP available     -> StateOpenFiltered (can't disambiguate)
//
// Without root/raw-ICMP access (the common case), SPECTRE cannot distinguish
// "open but silent" from "filtered by a firewall" — both look like silence to
// an unprivileged UDP socket. We report StateOpenFiltered in that case rather
// than guessing either way, matching Nmap's own documented behavior for the
// same constraint.
func scanUDPPorts(ctx context.Context, target string, ports []int, concurrency int, timeout time.Duration, ac *AdaptiveController) []UDPResult {
	icmp := newICMPListener(target) // nil if unavailable (non-root or unsupported platform)
	if icmp != nil {
		defer icmp.Close()
		go icmp.Listen(ctx)
	}

	work := make(chan int, concurrency*2)
	go func() {
		defer close(work)
		for _, p := range ports {
			select {
			case work <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	var mu sync.Mutex
	var results []UDPResult
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case port, ok := <-work:
					if !ok {
						return
					}
					r := probeUDPPort(ctx, target, port, timeout, icmp)
					if ac != nil {
						if r.State == StateClosed {
							ac.RecordICMPUnreachable()
						} else if r.State == StateOpenFiltered {
							ac.RecordTimeout()
						} else {
							ac.RecordSuccess()
						}
					}
					mu.Lock()
					results = append(results, r)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return results
}

func probeUDPPort(ctx context.Context, target string, port int, timeout time.Duration, icmp *icmpListener) UDPResult {
	addr := fmt.Sprintf("%s:%d", target, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return UDPResult{Port: port, State: StateFiltered}
	}
	defer conn.Close()

	payload := udpProbes[port] // nil is fine — Write(nil) sends a zero-length datagram
	_, _ = conn.Write(payload)

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		return UDPResult{Port: port, State: StateOpen, Banner: truncate(string(buf[:n]), 256)}
	}

	// No response. Check whether we positively observed an ICMP
	// port-unreachable for this port during the read window.
	if icmp != nil && icmp.SawUnreachable(target, port, timeout) {
		return UDPResult{Port: port, State: StateClosed}
	}

	// Silence with no ICMP confirmation: genuinely ambiguous between open and
	// filtered. Reported as such rather than guessed.
	return UDPResult{Port: port, State: StateOpenFiltered}
}

// icmpUnreachableKey identifies a (host, port) pair seen in an ICMP message.
type icmpUnreachableKey struct {
	host string
	port int
}

// icmpListener captures ICMP "destination unreachable / port unreachable"
// messages so UDP scanning can positively confirm StateClosed instead of
// treating all silence as ambiguous. Requires raw ICMP socket access
// (root/admin) — see icmp_unix.go / icmp_windows.go.
type icmpListener struct {
	mu   sync.Mutex
	seen map[icmpUnreachableKey]time.Time
	conn net.PacketConn
}

// SawUnreachable reports whether an ICMP port-unreachable for host:port was
// observed within the last `within` duration.
func (l *icmpListener) SawUnreachable(host string, port int, within time.Duration) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.seen[icmpUnreachableKey{host: host, port: port}]
	return ok && time.Since(t) <= within+time.Second
}

func (l *icmpListener) record(host string, port int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen[icmpUnreachableKey{host: host, port: port}] = time.Now()
}

func (l *icmpListener) Close() error {
	if l == nil || l.conn == nil {
		return nil
	}
	return l.conn.Close()
}

// Listen reads ICMP packets until ctx is cancelled, recording any
// port-unreachable messages so probeUDPPort can correlate them. Safe to call
// on a nil listener (no-op) so callers don't need a platform-specific guard.
func (l *icmpListener) Listen(ctx context.Context) {
	if l == nil || l.conn == nil {
		return
	}
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = l.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := l.conn.ReadFrom(buf)
		if err != nil {
			continue // timeout or transient error — keep listening until ctx is done
		}
		if host, port, ok := parseICMPPortUnreachable(buf[:n]); ok {
			l.record(host, port)
		}
	}
}

// parseICMPPortUnreachable extracts the (dest IP, dest port) embedded in an
// ICMP "destination unreachable, port unreachable" message's quoted original
// IP+UDP header. Returns ok=false if the packet isn't a type-3/code-3 ICMP
// message or doesn't carry enough of the original datagram to identify it.
func parseICMPPortUnreachable(buf []byte) (host string, port int, ok bool) {
	// ICMP header: type(1) code(1) checksum(2) unused(4) = 8 bytes, then the
	// original IP header + first 8 bytes of the original UDP header.
	if len(buf) < 8+20+8 {
		return "", 0, false
	}
	if buf[0] != 3 || buf[1] != 3 { // type 3 = dest unreachable, code 3 = port unreachable
		return "", 0, false
	}
	origIP := buf[8:]
	ihl := int(origIP[0]&0x0f) * 4
	if len(origIP) < ihl+8 {
		return "", 0, false
	}
	dstIP := net.IP(origIP[16:20])
	origUDP := origIP[ihl:]
	dstPort := int(binary.BigEndian.Uint16(origUDP[2:4]))
	return dstIP.String(), dstPort, true
}

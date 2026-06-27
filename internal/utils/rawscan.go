package utils

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// RawProbeResult is the outcome of one raw-socket TCP probe.
type RawProbeResult struct {
	GotResponse bool
	Flags       uint8 // flags observed in the response (SYN|ACK, RST, etc.)
}

// RawScanner sends crafted TCP packets via a raw IP socket and correlates
// responses by source port. One RawScanner should be shared across an entire
// scan phase: it opens a single listening raw socket and dispatches incoming
// packets to whichever probe is waiting on that (dstIP, srcPort) pair.
//
// Platform behavior (verified against Go's net package source, not just the
// generic raw(7) socket semantics):
//   - Linux/BSD: requires root or CAP_NET_RAW. Go's net.IPConn strips the IPv4
//     header internally (see stripIPv4Header in net/iprawsock_posix.go), so
//     ReadFromIP's buffer starts at byte 0 of the TCP header directly — no
//     extra offset needed when parsing srcPort/dstPort/flags below. On send,
//     the kernel itself prepends the IP header (we only write the TCP header).
//   - Windows: net.ListenIP("ip4:tcp", ...) fails to bind on every modern
//     Windows version (Vista+) because Windows forbids sending TCP data over
//     raw sockets, full stop — this is an OS-level restriction with no
//     elevation level that lifts it (see Microsoft's raw sockets doc and
//     https://github.com/golang/go/issues/23193). NewRawScanner will return an
//     error here every time, including under Administrator; callers must
//     treat that as expected and fall back to TCP-connect scanning rather
//     than retry or treat it as a transient failure.
//   - Known side-effect on Unix: because this bypasses the kernel's own TCP
//     state machine, the local kernel doesn't recognize the handshake and
//     will send its own RST when a real SYN-ACK arrives for our crafted SYN.
//     This doesn't corrupt our own classification (we read the genuine
//     SYN-ACK before the kernel's RST goes out), but it is an extra packet a
//     target-side IDS may observe. Suppressing it requires binding a dummy
//     listening socket on the ephemeral source port, which isn't implemented.
//
// Requires raw socket privilege (root/Administrator) — callers must check
// RawSockAvailable before constructing one, and must still handle a non-nil
// error from NewRawScanner since privilege alone doesn't guarantee the
// platform supports this (Windows being the standing example).
type RawScanner struct {
	conn      *net.IPConn // tcp-protocol raw socket for sending+receiving probes
	spoofConn *net.IPConn // raw IP socket (protocol 255) for spoofed/fragmented sends
	srcIP     net.IP

	mu      sync.Mutex
	waiters map[uint16]chan RawProbeResult
}

// NewRawScanner opens a raw IP socket for sending/receiving TCP segments
// directly (bypassing the kernel's TCP state machine, which is what lets us
// send SYN/FIN/NULL/XMAS probes without completing a real handshake).
// Returns an error on Windows unconditionally — see the RawScanner doc above.
//
// spoofConn is a separate raw socket bound to an unused protocol number (255)
// so we can write full IP datagrams (including custom source IPs and fragment
// fields) rather than just TCP payloads. This is needed for:
//   - Decoy scanning (spoofed source IP)
//   - Packet fragmentation (custom IP fragment offset/MF fields)
func NewRawScanner(srcIP net.IP) (*RawScanner, error) {
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	spoofConn, err := net.ListenIP("ip4:255", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		conn.Close()
		return nil, err
	}
	rs := &RawScanner{
		conn:      conn,
		spoofConn: spoofConn,
		srcIP:     srcIP,
		waiters:   make(map[uint16]chan RawProbeResult),
	}
	return rs, nil
}

// Close releases the underlying raw sockets.
func (rs *RawScanner) Close() error {
	var err1, err2 error
	if rs.conn != nil {
		err1 = rs.conn.Close()
	}
	if rs.spoofConn != nil {
		err2 = rs.spoofConn.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

// Listen reads incoming TCP segments until ctx is cancelled, dispatching each
// to the waiter registered for its destination port (our source port on the
// original probe). Must be run in its own goroutine for the lifetime of the
// scan phase.
func (rs *RawScanner) Listen(ctx context.Context) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = rs.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := rs.conn.ReadFromIP(buf)
		if err != nil {
			continue // read timeout — loop and check ctx again
		}
		if n < 20 {
			continue // shorter than a TCP header; not a usable response
		}
		srcPort := binary.BigEndian.Uint16(buf[0:2])
		dstPort := binary.BigEndian.Uint16(buf[2:4])
		flags := buf[13]

		// The response's destination port is our original source port.
		rs.mu.Lock()
		ch, ok := rs.waiters[dstPort]
		rs.mu.Unlock()
		if ok {
			select {
			case ch <- RawProbeResult{GotResponse: true, Flags: flags}:
			default:
			}
		}
		_ = srcPort // kept for clarity/debugging; not currently branched on
	}
}

// Probe sends one crafted TCP segment with the given flags to dstIP:dstPort
// and waits up to timeout for a correlated response.
func (rs *RawScanner) Probe(ctx context.Context, dstIP net.IP, dstPort int, flags uint8, timeout time.Duration) (RawProbeResult, error) {
	srcPort := RandomPort()

	ch := make(chan RawProbeResult, 1)
	rs.mu.Lock()
	rs.waiters[srcPort] = ch
	rs.mu.Unlock()
	defer func() {
		rs.mu.Lock()
		delete(rs.waiters, srcPort)
		rs.mu.Unlock()
	}()

	pkt := CraftTCP(TCPPacket{
		SrcIP:   rs.srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: uint16(dstPort),
		Flags:   flags,
	})
	// net.IPConn with "ip4:tcp" expects the payload starting at the transport
	// header — CraftTCP returns ip+tcp combined, so skip the 20-byte IP header
	// the kernel will reconstruct itself for IPPROTO_TCP raw sends.
	tcpOnly := pkt[20:]

	if _, err := rs.conn.WriteToIP(tcpOnly, &net.IPAddr{IP: dstIP}); err != nil {
		return RawProbeResult{}, err
	}

	select {
	case r := <-ch:
		return r, nil
	case <-time.After(timeout):
		return RawProbeResult{GotResponse: false}, nil
	case <-ctx.Done():
		return RawProbeResult{}, ctx.Err()
	}
}

// SendSpoofedTCP sends a single spoofed TCP packet using the given spoofed
// srcIP as the apparent source. This is fire-and-forget: no response is read
// or correlated, so it is suitable for decoy scanning where the goal is only
// to create noise that obscures the true scanner IP.
//
// The full datagram (IP+TCP) is written to spoofConn (protocol 255) so we
// control the IP source address, which the normal tcp-protocol socket does not
// allow on Linux (the kernel overwrites it with the outbound interface address).
func (rs *RawScanner) SendSpoofedTCP(dstIP, srcIP net.IP, dstPort int, flags uint8) error {
	// Validate srcIP is IPv4 before crafting — To4() returning nil would cause
	// a nil-dereference inside CraftTCP.
	if srcIP.To4() == nil {
		return nil // silently skip non-IPv4 decoys
	}
	srcPort := RandomPort()
	pkt := CraftTCP(TCPPacket{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: uint16(dstPort),
		Flags:   flags,
	})
	_, err := rs.spoofConn.WriteToIP(pkt, &net.IPAddr{IP: dstIP})
	return err
}

// ProbeFragmented sends a TCP probe split across two IP fragments and waits
// for a correlated response. This causes stateless IDS/IPS signature matchers
// that only inspect the first fragment to miss the TCP flags field.
//
// mtu specifies how many bytes of the TCP header to place in the first
// fragment. It is automatically:
//   - Aligned down to the nearest multiple of 8 (RFC 791 requires offsets in
//     8-byte units; misalignment produces overlapping or gapped fragments that
//     modern kernels silently discard).
//   - Clamped to [8, len(tcpHeader)-8] so both fragments are non-empty and the
//     second fragment actually contains the flags byte (offset 13).
//
// If the resulting aligned mtu would leave an empty second fragment, the probe
// falls back to an unfragmented Probe() call.
func (rs *RawScanner) ProbeFragmented(ctx context.Context, dstIP net.IP, dstPort int, flags uint8, timeout time.Duration, mtu int) (RawProbeResult, error) {
	srcPort := RandomPort()

	ch := make(chan RawProbeResult, 1)
	rs.mu.Lock()
	rs.waiters[srcPort] = ch
	rs.mu.Unlock()
	defer func() {
		rs.mu.Lock()
		delete(rs.waiters, srcPort)
		rs.mu.Unlock()
	}()

	pkt := CraftTCP(TCPPacket{
		SrcIP:   rs.srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: uint16(dstPort),
		Flags:   flags,
	})
	tcpOnly := pkt[20:] // 20-byte TCP header

	// Align mtu down to nearest multiple of 8 (IP fragment offset unit).
	mtu = (mtu / 8) * 8
	if mtu < 8 {
		mtu = 8
	}
	// Ensure second fragment is non-empty.
	if mtu >= len(tcpOnly) {
		mtu = len(tcpOnly) - 8
	}
	if mtu < 8 {
		// TCP header too short to split meaningfully; fall back to plain probe.
		return rs.Probe(ctx, dstIP, dstPort, flags, timeout)
	}

	// Use crypto/rand for fragment ID so IDS cannot correlate fragment pairs
	// across different probes by tracking sequential ID values.
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return RawProbeResult{}, err
	}
	id := binary.BigEndian.Uint16(idBuf[:])

	payload1 := tcpOnly[:mtu]
	payload2 := tcpOnly[mtu:]

	frag1 := CraftIPFragment(rs.srcIP, dstIP, id, true, 0, payload1)
	// offset for frag2 in 8-byte units
	frag2 := CraftIPFragment(rs.srcIP, dstIP, id, false, uint16(mtu/8), payload2)

	if _, err := rs.spoofConn.WriteToIP(frag1, &net.IPAddr{IP: dstIP}); err != nil {
		return RawProbeResult{}, err
	}
	if _, err := rs.spoofConn.WriteToIP(frag2, &net.IPAddr{IP: dstIP}); err != nil {
		return RawProbeResult{}, err
	}

	select {
	case r := <-ch:
		return r, nil
	case <-time.After(timeout):
		return RawProbeResult{GotResponse: false}, nil
	case <-ctx.Done():
		return RawProbeResult{}, ctx.Err()
	}
}

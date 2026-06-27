package utils

import (
	"crypto/rand"
	"encoding/binary"
	"net"
)

// RawSockAvailable reports whether raw socket access is possible.
// Requires root on Linux, or elevated privileges on Windows.
// This is a build-time detection; actual availability is tested at runtime.
var RawSockAvailable = checkRawSock()

// TCPFlags used for crafting raw packets.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
	FlagURG = 0x20
)

// TCPPacket holds a minimal representation of a raw TCP packet for crafting.
type TCPPacket struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Flags   uint8
	SeqNum  uint32
	AckNum  uint32
	Window  uint16
}

// cryptoUint32 returns a cryptographically random uint32.
// Falls back to 0 on failure (extremely unlikely; callers treat 0 as
// "generate random" in SeqNum, so a failure simply triggers re-generation
// from the same source, which will also fail — acceptable edge case).
func cryptoUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint32(b[:])
}

// cryptoUint16 returns a cryptographically random uint16.
func cryptoUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 10000 // safe fallback
	}
	return binary.BigEndian.Uint16(b[:])
}

// CraftTCP builds a raw TCP+IP packet. Returns the full IP datagram as bytes.
// Only IPv4 is supported. Suitable for writing to a raw SOCK_RAW socket.
// SeqNum and IP ID are generated with crypto/rand so they are unpredictable
// and cannot be fingerprinted or used to correlate/disrupt the scan via RST
// injection.
func CraftTCP(pkt TCPPacket) []byte {
	if pkt.Window == 0 {
		pkt.Window = 65535
	}
	if pkt.SeqNum == 0 {
		pkt.SeqNum = cryptoUint32()
	}

	// TCP header (20 bytes, no options)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], pkt.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:], pkt.DstPort)
	binary.BigEndian.PutUint32(tcp[4:], pkt.SeqNum)
	binary.BigEndian.PutUint32(tcp[8:], pkt.AckNum)
	tcp[12] = 0x50 // data offset = 5 (20 bytes), reserved = 0
	tcp[13] = pkt.Flags
	binary.BigEndian.PutUint16(tcp[14:], pkt.Window)
	// checksum computed below
	binary.BigEndian.PutUint16(tcp[16:], 0)
	binary.BigEndian.PutUint16(tcp[18:], 0) // urgent pointer

	// TCP checksum requires pseudo-header
	checksum := tcpChecksum(pkt.SrcIP.To4(), pkt.DstIP.To4(), tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum)

	// IP header (20 bytes)
	ip := make([]byte, 20)
	ip[0] = 0x45 // version=4, IHL=5
	ip[1] = 0x00 // DSCP/ECN
	totalLen := uint16(40)
	binary.BigEndian.PutUint16(ip[2:], totalLen)
	// Use crypto/rand for IP ID to prevent ID-based OS fingerprinting and
	// RST injection attacks that rely on predictable ID sequences.
	binary.BigEndian.PutUint16(ip[4:], cryptoUint16())
	binary.BigEndian.PutUint16(ip[6:], 0x4000) // DF flag
	ip[8] = 64                                  // TTL
	ip[9] = 6                                   // protocol TCP
	binary.BigEndian.PutUint16(ip[10:], 0)      // checksum placeholder
	copy(ip[12:], pkt.SrcIP.To4())
	copy(ip[16:], pkt.DstIP.To4())
	ipCS := ipChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:], ipCS)

	return append(ip, tcp...)
}

// RandomPort returns a cryptographically random high-numbered source port
// (10000–65535). Unpredictable source ports prevent fixed-source-port
// signatures and reduce the risk of RST injection against known ports.
func RandomPort() uint16 {
	// Range [10000, 65535] = 55536 values
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 32768 // safe static fallback
	}
	v := binary.BigEndian.Uint16(b[:])
	return 10000 + (v % 55536)
}

// CraftIPFragment builds an IPv4 datagram with explicit fragment fields.
// Used to split a TCP probe across two IP fragments so that stateless IDS/IPS
// signature matching (which only inspects the first fragment) misses the TCP
// flags field.
//
//   - id:      IP Identification field — same value across both fragments
//     (use crypto/rand so pairs cannot be trivially correlated externally).
//   - mf:      "More Fragments" bit; true for all but the last fragment.
//   - offset:  Fragment offset in units of 8 bytes (RFC 791 §3.1).
//   - payload: Raw bytes that follow the IP header in this fragment.
func CraftIPFragment(srcIP, dstIP net.IP, id uint16, mf bool, offset uint16, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // version=4, IHL=5
	ip[1] = 0x00 // DSCP/ECN
	totalLen := uint16(20 + len(payload))
	binary.BigEndian.PutUint16(ip[2:], totalLen)
	binary.BigEndian.PutUint16(ip[4:], id)

	var flagsAndOffset uint16
	if mf {
		flagsAndOffset |= 0x2000 // MF bit (bit 13 of flags+offset field)
	}
	flagsAndOffset |= offset & 0x1FFF // low 13 bits are the offset
	binary.BigEndian.PutUint16(ip[6:], flagsAndOffset)

	ip[8] = 64 // TTL
	ip[9] = 6  // protocol TCP
	binary.BigEndian.PutUint16(ip[10:], 0) // checksum placeholder
	copy(ip[12:], srcIP.To4())
	copy(ip[16:], dstIP.To4())
	ipCS := ipChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:], ipCS)

	return append(ip, payload...)
}

func ipChecksum(header []byte) uint16 {
	return checksum(header)
}

func tcpChecksum(srcIP, dstIP []byte, tcpHeader []byte) uint16 {
	// Pseudo-header: src, dst, zero, proto=6, tcp length
	pseudo := make([]byte, 12+len(tcpHeader))
	copy(pseudo[0:], srcIP)
	copy(pseudo[4:], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcpHeader)))
	copy(pseudo[12:], tcpHeader)
	return checksum(pseudo)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checkRawSock attempts to detect if raw sockets are available.
// Returns false on error (no privilege); callers fall back to connect scan.
func checkRawSock() bool {
	return rawSockAvailable()
}

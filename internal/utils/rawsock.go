package utils

import (
	"encoding/binary"
	"math/rand"
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

// CraftTCP builds a raw TCP+IP packet. Returns the full IP datagram as bytes.
// Only IPv4 is supported. Suitable for writing to a raw SOCK_RAW socket.
func CraftTCP(pkt TCPPacket) []byte {
	if pkt.Window == 0 {
		pkt.Window = 65535
	}
	if pkt.SeqNum == 0 {
		pkt.SeqNum = rand.Uint32()
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
	binary.BigEndian.PutUint16(ip[4:], uint16(rand.Uint32())) // ID
	binary.BigEndian.PutUint16(ip[6:], 0x4000)                // DF flag
	ip[8] = 64                                                 // TTL
	ip[9] = 6                                                  // protocol TCP
	binary.BigEndian.PutUint16(ip[10:], 0)                    // checksum placeholder
	copy(ip[12:], pkt.SrcIP.To4())
	copy(ip[16:], pkt.DstIP.To4())
	ipCS := ipChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:], ipCS)

	return append(ip, tcp...)
}

// RandomPort returns a random high-numbered source port.
func RandomPort() uint16 {
	return uint16(rand.Intn(55535) + 10000)
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

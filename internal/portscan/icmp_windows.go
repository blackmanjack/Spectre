//go:build windows

package portscan

// newICMPListener is not implemented on Windows: raw ICMP capture requires
// either WinPcap/Npcap or SIO_RCVALL on a raw socket under Administrator
// privileges, neither of which this build wires up. Returns nil so UDP
// scanning falls back to silence-only classification (StateOpenFiltered)
// rather than fabricating an ICMP-based "closed" determination it can't
// actually observe.
func newICMPListener(target string) *icmpListener {
	return nil
}

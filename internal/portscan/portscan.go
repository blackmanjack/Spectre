package portscan

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spectre-tool/spectre/internal/evasion"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options holds all port scanner configuration.
type Options struct {
	Target      string
	PortSpec    string // "80,443", "1-1000", "-" (all), "top:1000"
	AllPorts    bool
	TopN        int
	Concurrency int
	Timeout     time.Duration
	RatePerSec  float64
	ScanType    string   // syn|connect|fin|null|xmas|ack
	Decoys      []string // decoy source IPs (raw-socket scans only; "ME" = real outbound IP)
	Fragment    bool     // split TCP header across two IP fragments
	FragMTU     int      // bytes of TCP header in first fragment (default 8)
	UDP         bool
	Service     bool  // enable banner/service detection
	OS          bool  // enable OS fingerprinting
	Retry       int
	Adaptive    bool
	Timing      string // T0-T5 or paranoid/sneaky/polite/normal/aggressive/insane
	Silent      bool   // suppress progress output
	EmbeddedFS  fs.FS
	Writer      output.Writer
}

// Run executes the 5-phase port scanner.
func Run(ctx context.Context, opts Options) (ScanSummary, error) {
	start := time.Now()
	summary := ScanSummary{Target: opts.Target, StartTime: start}

	// Resolve port list
	ports := resolvePortSpec(opts)

	// Timing template drives more than just rate: T0-T2 (paranoid/sneaky/polite)
	// also shuffle probe order so there's no sequential-sweep signature, and
	// jitter each probe's delay so cadence isn't a fixed, easily-fingerprinted
	// pattern. T3+ skip the per-probe jitter sleep — at that speed the jitter
	// range is sub-millisecond and not worth the scheduling overhead.
	tmpl := evasion.GetTemplate(opts.Timing)
	evasion.ShuffleInts(ports)
	useJitter := opts.Timing == "T0" || opts.Timing == "T1" || opts.Timing == "T2" ||
		opts.Timing == "paranoid" || opts.Timing == "sneaky" || opts.Timing == "polite"

	// Load databases
	probeDB, _ := LoadProbeDB(opts.EmbeddedFS)
	osDB := LoadOSDB(opts.EmbeddedFS)

	// Set up rate limiting (respects timing template)
	rps := timingToRPS(opts.Timing, opts.RatePerSec)
	rl := utils.NewRateLimiter(rps)

	var ac *AdaptiveController
	if opts.Adaptive {
		ac = NewAdaptiveController(rl, rps)
	}

	// Raw-socket scan types (syn/fin/null/xmas/ack) need a privileged raw IP
	// socket to send crafted segments and correlate responses. If that's not
	// available, fall back to connect-scan confirmation and say so explicitly
	// — never silently relabel a connect-scan result as if it came from SYN.
	rawOnlyTypes := map[string]bool{"syn": true, "fin": true, "null": true, "xmas": true, "ack": true}
	var rawScanner *utils.RawScanner
	var srcIP net.IP // outbound source IP; also used for "ME" decoy substitution
	if rawOnlyTypes[opts.ScanType] {
		if !utils.RawSockAvailable {
			fmt.Fprintf(os.Stderr, "[warn] Raw socket unavailable (no root/admin) for --scan-type=%s — using TCP connect scan\n", opts.ScanType)
			opts.ScanType = "connect"
		} else {
			srcIP = outboundIP(opts.Target)
			if srcIP == nil {
				fmt.Fprintf(os.Stderr, "[warn] Could not determine outbound source IP for --scan-type=%s — using TCP connect scan\n", opts.ScanType)
				opts.ScanType = "connect"
			} else {
				var err error
				rawScanner, err = utils.NewRawScanner(srcIP)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[warn] Failed to open raw socket for --scan-type=%s (%v) — using TCP connect scan\n", opts.ScanType, err)
					opts.ScanType = "connect"
				} else {
					defer rawScanner.Close()
					go rawScanner.Listen(ctx)
				}
			}
		}
	}

	// Resolve decoy specs: substitute "ME" with outbound IP, validate IPv4.
	var resolvedDecoys []string
	if len(opts.Decoys) > 0 {
		if rawScanner == nil {
			fmt.Fprintln(os.Stderr, "[warn] Decoy scanning requires a raw socket (use a raw --scan-type) — skipping decoys")
		} else {
			for _, d := range opts.Decoys {
				if d == "ME" {
					if srcIP != nil {
						resolvedDecoys = append(resolvedDecoys, srcIP.String())
					}
				} else if net.ParseIP(d).To4() != nil {
					// Only accept valid IPv4 addresses; reject IPv6 and garbage.
					resolvedDecoys = append(resolvedDecoys, d)
				} else {
					fmt.Fprintf(os.Stderr, "[warn] Decoy %q is not a valid IPv4 address — skipping\n", d)
				}
			}
		}
	}

	if opts.Fragment && rawScanner == nil {
		fmt.Fprintln(os.Stderr, "[warn] Packet fragmentation requires a raw socket (use a raw --scan-type) — skipping fragmentation")
	}

	summary.Total = len(ports)

	// ── Phase 1: Discovery ──────────────────────────────────────────────────
	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "[spectre] Phase 1: Discovery — %d ports, concurrency=%d\n", len(ports), opts.Concurrency)
	}
	candidates := discoverOpenPorts(ctx, opts.Target, ports, opts.Concurrency, opts.Timeout, rl, ac, tmpl, useJitter)

	if len(candidates) == 0 {
		summary.Duration = time.Since(start).String()
		return summary, nil
	}
	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "[spectre] Phase 1 done: %d candidates\n", len(candidates))
	}

	// ── Phase 2: Multi-probe confirmation ──────────────────────────────────
	var confirmed []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan int, opts.Concurrency)

	go func() {
		defer close(work)
		for _, p := range candidates {
			select {
			case work <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range work {
				if err := rl.Wait(ctx); err != nil {
					return
				}
				state := confirmPort(ctx, opts.Target, port, opts.Timeout, opts.Retry, opts.ScanType, rawScanner, resolvedDecoys, opts.Fragment, opts.FragMTU)
				if state == StateOpen || state == StateOpenFiltered {
					r := PortResult{
						Port:      port,
						Protocol:  "tcp",
						State:     state,
						Timestamp: time.Now(),
					}
					mu.Lock()
					confirmed = append(confirmed, r)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "[spectre] Phase 2 done: %d confirmed open\n", len(confirmed))
	}

	// ── Phase 4: Service/banner detection ─────────────────────────────────
	if opts.Service && len(confirmed) > 0 {
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[spectre] Phase 4: Service detection\n")
		}
		svcTimeout := opts.Timeout + 2*time.Second
		for i := range confirmed {
			svc, ver, banner, conf := serviceDetect(ctx, opts.Target, confirmed[i].Port, probeDB, svcTimeout)
			confirmed[i].Service = svc
			confirmed[i].Version = ver
			confirmed[i].Banner = banner
			confirmed[i].Confidence = conf
		}
	}

	// ── Phase 3: UDP scan ───────────────────────────────────────────────────
	if opts.UDP {
		udpPorts := ports
		if len(udpPorts) > 1000 && opts.TopN == 0 && !opts.AllPorts {
			udpPorts = topPorts(1000) // UDP is slower per-port; cap unless explicitly requested
		}
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[spectre] Phase 3: UDP scan — %d ports\n", len(udpPorts))
		}
		udpResults := scanUDPPorts(ctx, opts.Target, udpPorts, opts.Concurrency, opts.Timeout, ac)
		for _, r := range udpResults {
			if r.State != StateOpen && r.State != StateOpenFiltered {
				continue
			}
			confirmed = append(confirmed, PortResult{
				Port:      r.Port,
				Protocol:  "udp",
				State:     r.State,
				Service:   guessServiceByPort(r.Port),
				Banner:    r.Banner,
				Timestamp: time.Now(),
			})
		}
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[spectre] Phase 3 done: %d UDP results (open or open|filtered)\n", len(udpResults))
		}
	}

	// ── Phase 5: OS detection ──────────────────────────────────────────────
	var osResult OSResult
	if opts.OS && len(confirmed) > 0 {
		ttl, win, measured := MeasureTCPParams(opts.Target, confirmed[0].Port, opts.Timeout)
		if measured {
			osResult = PassiveOSDetect(osDB, ttl, win)
			summary.OS = osResult
			if !opts.Silent {
				fmt.Fprintf(os.Stderr, "[spectre] OS: %s (%d%% confidence)\n", osResult.Name, osResult.Confidence)
			}
		} else if !opts.Silent {
			fmt.Fprintln(os.Stderr, "[spectre] OS: unavailable on this platform/connection (no fabricated guess)")
		}
	}

	// ── Emit results ───────────────────────────────────────────────────────
	var found int64
	for _, r := range confirmed {
		if err := opts.Writer.Write(output.Result{
			Type:       output.TypePort,
			Value:      fmt.Sprintf("%s:%d", opts.Target, r.Port),
			Port:       r.Port,
			Protocol:   r.Protocol,
			State:      r.State.String(),
			Service:    r.Service,
			Version:    r.Version,
			Banner:     r.Banner,
			Confidence: r.Confidence,
			OS:         osResult.Name,
			Timestamp:  r.Timestamp,
		}); err == nil {
			atomic.AddInt64(&found, 1)
		}
	}

	summary.OpenPorts = confirmed
	summary.Duration = time.Since(start).String()
	return summary, nil
}

// confirmPort re-verifies a Phase 1 candidate.
//
// With a *utils.RawScanner (scanType is one of syn/fin/null/xmas/ack and raw
// socket privilege was available), this sends the actual crafted probe and
// classifies the state from the real response per RFC 793 semantics:
//
//	SYN  -> SYN+ACK received = open；RST received = closed；silence = filtered
//	ACK  -> RST received = unfiltered (stateless fw passes ACK)；silence = filtered
//	FIN/NULL/XMAS -> RST received = closed；silence = open|filtered (RFC 793:
//	                  compliant stacks send nothing for an open port)
//
// Without a RawScanner (the common case — no root/admin, or --scan-type
// connect), this falls back to TCP-connect confirmation, which can only
// distinguish open from not-open; it cannot discriminate filtered vs closed.
func confirmPort(ctx context.Context, target string, port int, timeout time.Duration, retry int, scanType string, raw *utils.RawScanner, decoys []string, fragment bool, fragMTU int) PortState {
	if raw != nil {
		return confirmPortRaw(ctx, target, port, timeout, retry, scanType, raw, decoys, fragment, fragMTU)
	}
	for i := 0; i <= retry; i++ {
		if connectProbe(ctx, target, port, timeout) {
			return StateOpen
		}
	}
	// Port didn't respond — determine filtered vs closed
	// (Without the raw-socket multi-probe path we can't distinguish; return filtered)
	return StateFiltered
}

// confirmPortRaw implements the real SYN/FIN/NULL/XMAS/ACK probe semantics
// described above, using a shared RawScanner for send+correlate.
//
// If fragment is true, the TCP probe is sent as two IP fragments (splitting
// the header at fragMTU bytes) so stateless IDS/IPS misses the TCP flags.
// After sending the real probe, decoy packets (spoofed source IPs) are
// fire-and-forgotten in shuffled order to obscure the true scanner IP.
func confirmPortRaw(ctx context.Context, target string, port int, timeout time.Duration, retry int, scanType string, raw *utils.RawScanner, decoys []string, fragment bool, fragMTU int) PortState {
	dstIP := net.ParseIP(target)
	if dstIP == nil {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return StateFiltered
		}
		dstIP = ips[0].To4()
		if dstIP == nil {
			return StateFiltered // raw scanner is IPv4-only
		}
	}

	var flags uint8
	switch scanType {
	case "syn":
		flags = utils.FlagSYN
	case "ack":
		flags = utils.FlagACK
	case "fin":
		flags = utils.FlagFIN
	case "null":
		flags = 0
	case "xmas":
		flags = utils.FlagFIN | utils.FlagURG | utils.FlagPSH
	default:
		flags = utils.FlagSYN
	}

	// Send the real probe (possibly fragmented).
	var lastResult utils.RawProbeResult
	for i := 0; i <= retry; i++ {
		var r utils.RawProbeResult
		var err error
		if fragment {
			r, err = raw.ProbeFragmented(ctx, dstIP, port, flags, timeout, fragMTU)
		} else {
			r, err = raw.Probe(ctx, dstIP, port, flags, timeout)
		}
		if err != nil {
			return StateFiltered
		}
		lastResult = r
		if r.GotResponse {
			break
		}
	}

	// Send decoy packets (spoofed source IPs, fire-and-forget).
	// Shuffle order so no fixed pattern reveals which IP is real.
	if len(decoys) > 0 {
		shuffled := make([]string, len(decoys))
		copy(shuffled, decoys)
		evasion.ShuffleStrings(shuffled)
		for _, decoy := range shuffled {
			decoyIP := net.ParseIP(decoy)
			if decoyIP != nil {
				// SendSpoofedTCP validates IPv4 internally; ignore send errors
				// (decoys are best-effort; a failed decoy doesn't affect accuracy).
				_ = raw.SendSpoofedTCP(dstIP, decoyIP, port, flags)
			}
		}
	}

	switch scanType {
	case "syn":
		if lastResult.GotResponse && lastResult.Flags&utils.FlagRST != 0 {
			return StateClosed
		}
		if lastResult.GotResponse && lastResult.Flags&utils.FlagSYN != 0 && lastResult.Flags&utils.FlagACK != 0 {
			return StateOpen
		}
		return StateFiltered
	case "ack":
		if lastResult.GotResponse && lastResult.Flags&utils.FlagRST != 0 {
			return StateUnfiltered
		}
		return StateFiltered
	default: // fin, null, xmas — RFC 793: open ports stay silent
		if lastResult.GotResponse && lastResult.Flags&utils.FlagRST != 0 {
			return StateClosed
		}
		return StateOpenFiltered
	}
}

// outboundIP determines which local IP the kernel would use to reach target,
// by opening a throwaway UDP "connection" (no packet is actually sent — UDP
// dial just resolves the route) and reading its local address.
func outboundIP(target string) net.IP {
	conn, err := net.Dial("udp4", net.JoinHostPort(target, "80"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return addr.IP
}

// resolvePortSpec turns Options into a list of port integers.
func resolvePortSpec(opts Options) []int {
	if opts.AllPorts {
		return expandPortRange("-")
	}
	if opts.TopN > 0 {
		return topPorts(opts.TopN)
	}
	if opts.PortSpec != "" {
		return expandPortRange(opts.PortSpec)
	}
	return topPorts(1000)
}

// timingToRPS maps a timing template name to a requests/second value.
func timingToRPS(timing string, userRPS float64) float64 {
	if userRPS > 0 {
		return userRPS
	}
	switch timing {
	case "T0", "paranoid":
		return 1
	case "T1", "sneaky":
		return 10
	case "T2", "polite":
		return 100
	case "T3", "normal":
		return 1000
	case "T4", "aggressive":
		return 3000
	case "T5", "insane":
		return 10000
	default:
		return 5000 // default: fast
	}
}


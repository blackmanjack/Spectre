package portscan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"

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
	ScanType    string // syn|connect|fin|null|xmas|ack
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

	if !utils.RawSockAvailable && (opts.ScanType == "syn" || opts.ScanType == "") {
		fmt.Fprintln(os.Stderr, "[warn] Raw socket unavailable (no root/admin) — using TCP connect scan")
		opts.ScanType = "connect"
	}

	summary.Total = len(ports)

	// ── Phase 1: Discovery ──────────────────────────────────────────────────
	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "[spectre] Phase 1: Discovery — %d ports, concurrency=%d\n", len(ports), opts.Concurrency)
	}
	candidates := discoverOpenPorts(ctx, opts.Target, ports, opts.Concurrency, opts.Timeout, rl, ac)

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
			work <- p
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
				state := confirmPort(ctx, opts.Target, port, opts.Timeout, opts.Retry)
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

	// ── Phase 5: OS detection ──────────────────────────────────────────────
	var osResult OSResult
	if opts.OS && len(confirmed) > 0 {
		// Passive first: use TTL from first open port
		ttl, win := MeasureTCPParams(opts.Target, confirmed[0].Port)
		osResult = PassiveOSDetect(osDB, ttl, win)
		if osResult.Name == "" || osResult.Confidence < 50 {
			// Fall back to TTL-only guess
			osResult = PassiveOSDetect(osDB, 64, 0) // default guess
		}
		summary.OS = osResult
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[spectre] OS: %s (%d%% confidence)\n", osResult.Name, osResult.Confidence)
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

// confirmPort probes a port with multiple techniques to confirm its state.
func confirmPort(ctx context.Context, target string, port int, timeout time.Duration, retry int) PortState {
	// TCP connect is our reliable fallback for state confirmation
	for i := 0; i <= retry; i++ {
		if connectProbe(ctx, target, port, timeout) {
			return StateOpen
		}
	}
	// Port didn't respond — determine filtered vs closed
	// (Without raw sockets we can't distinguish; return filtered)
	return StateFiltered
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


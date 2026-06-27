package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/evasion"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/portscan"
)

var portscanCmd = &cobra.Command{
	Use:   "portscan",
	Short: "Port scanner — 5-phase pipeline surpassing Nmap + RustScan",
	Example: `  spectre portscan -t 192.168.1.1 --all-ports
  sudo spectre portscan -t 10.0.0.5 --all-ports --service --os --udp --timing aggressive
  sudo spectre portscan -t 10.0.0.5 --scan-type syn --decoys "10.0.0.9,ME" --fragment
  spectre portscan -t 192.168.1.0/24 -p 1-10000 --top-ports 1000 -f json`,
	RunE: runPortScan,
}

var (
	psTarget      string
	psPorts       string
	psAllPorts    bool
	psTopPorts    int
	psConcurrency int
	psTimeout     int
	psRate        float64
	psScanType    string
	psUDP         bool
	psService     bool
	psOS          bool
	psRetry       int
	psAdaptive    bool
	psTiming      string
	psDecoys      string
	psFragment    bool
	psFragMTU     int
)

func init() {
	f := portscanCmd.Flags()
	f.StringVarP(&psTarget, "target", "t", "", "Target IP/CIDR/hostname (required)")
	f.StringVarP(&psPorts, "ports", "p", "", "Port specification: 80,443 or 1-1000 or - (all)")
	f.BoolVar(&psAllPorts, "all-ports", false, "Scan all 65535 ports")
	f.IntVar(&psTopPorts, "top-ports", 0, "Scan top N common ports")
	f.IntVarP(&psConcurrency, "concurrency", "c", 5000, "Discovery goroutines")
	f.IntVar(&psTimeout, "timeout", 800, "Per-port timeout (milliseconds)")
	f.Float64VarP(&psRate, "rate", "r", 0, "Packets/sec (0 = use --timing template)")
	f.StringVar(&psScanType, "scan-type", "connect", "Scan type: connect|syn|fin|null|xmas|ack. syn/fin/null/xmas/ack need root/admin for a raw socket and fall back to connect with a warning if unavailable")
	f.BoolVar(&psUDP, "udp", false, "Also run UDP scan (root/admin needed for ICMP-correlated closed-port detection; falls back to open|filtered without it)")
	f.BoolVar(&psService, "service", false, "Enable service/banner detection")
	f.BoolVar(&psOS, "os", false, "Enable OS fingerprinting")
	f.IntVar(&psRetry, "retry", 2, "Retries per port")
	f.BoolVar(&psAdaptive, "adaptive", true, "Enable adaptive rate control")
	f.StringVar(&psTiming, "timing", "T4", "Timing template: T0-T5 or paranoid/sneaky/polite/normal/aggressive/insane")
	f.StringVar(&psDecoys, "decoys", "", "Decoy source IPs to interleave (e.g. \"10.0.0.1,10.0.0.2,ME\"). Raw scan-type required.")
	f.BoolVar(&psFragment, "fragment", false, "Split TCP header across two IP fragments (raw scan-type required; defeats stateless IDS/IPS signature matching)")
	f.IntVar(&psFragMTU, "mtu", 8, "Bytes of TCP header in first IP fragment (must be a multiple of 8; minimum 8)")
	_ = portscanCmd.MarkFlagRequired("target")
	rootCmd.AddCommand(portscanCmd)
}

func runPortScan(cmd *cobra.Command, args []string) error {
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(psTarget); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("portscan", psTarget, scopeFile, map[string]any{
			"ports": psPorts, "all": psAllPorts, "service": psService, "os": psOS,
			"decoys": psDecoys, "fragment": psFragment,
		})
		defer globalAudit.Close()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	dest := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		dest = f
	}

	if !silent {
		fmt.Fprintf(os.Stderr, "[spectre] portscan: %s\n", psTarget)
	}

	writer := output.NewWriter(outputFmt, dest, noColor)

	opts := portscan.Options{
		Target:      psTarget,
		PortSpec:    psPorts,
		AllPorts:    psAllPorts,
		TopN:        psTopPorts,
		Concurrency: psConcurrency,
		Timeout:     time.Duration(psTimeout) * time.Millisecond,
		RatePerSec:  psRate,
		ScanType:    psScanType,
		Decoys:      evasion.DecoyList(psDecoys),
		Fragment:    psFragment,
		FragMTU:     psFragMTU,
		UDP:         psUDP,
		Service:     psService,
		OS:          psOS,
		Retry:       psRetry,
		Adaptive:    psAdaptive,
		Timing:      psTiming,
		Silent:      silent,
		EmbeddedFS:  embeddedFS,
		Writer:      writer,
	}

	summary, err := portscan.Run(ctx, opts)
	if err != nil {
		return err
	}
	_ = writer.Flush()

	if !silent {
		fmt.Fprintf(os.Stderr, "\n[spectre] %d open ports found (of %d scanned) in %s\n",
			len(summary.OpenPorts), summary.Total, summary.Duration)
		if summary.OS.Name != "" {
			fmt.Fprintf(os.Stderr, "[spectre] OS: %s (%d%% confidence)\n",
				summary.OS.Name, summary.OS.Confidence)
		}
	}
	return nil
}

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/dnsrecon"
	"github.com/spectre-tool/spectre/internal/output"
)

var dnsCmd = &cobra.Command{
	Use:   "dns [domain]",
	Short: "DNS recon — A/AAAA/MX/NS/TXT/PTR records, zone transfer attempt",
	Args:  cobra.ExactArgs(1),
	RunE:  runDNS,
}

var (
	dnsResolvers string
	dnsTimeout   int
	dnsAxfr      bool
)

func init() {
	f := dnsCmd.Flags()
	f.StringVar(&dnsResolvers, "resolvers", "8.8.8.8:53,1.1.1.1:53", "DNS resolvers (ip:port)")
	f.IntVar(&dnsTimeout, "timeout", 10, "Query timeout (seconds)")
	f.BoolVar(&dnsAxfr, "axfr", true, "Attempt zone transfer (AXFR) per NS")
	rootCmd.AddCommand(dnsCmd)
}

func runDNS(cmd *cobra.Command, args []string) error {
	domain := args[0]
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(domain); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("dns", domain, scopeFile, nil)
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

	writer := output.NewWriter(outputFmt, dest, noColor)
	defer writer.Close()

	if !silent {
		fmt.Fprintf(os.Stderr, "[spectre] dns recon: %s\n", domain)
	}

	return dnsrecon.Run(ctx, dnsrecon.Options{
		Domain:    domain,
		Resolvers: parseComma(dnsResolvers),
		Timeout:   time.Duration(dnsTimeout) * time.Second,
		TryAxfr:   dnsAxfr,
		Writer:    writer,
	})
}

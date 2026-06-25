package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/webtech"
)

var webtechCmd = &cobra.Command{
	Use:   "webtech [url]",
	Short: "Web technology fingerprinting — headers, cookies, body signatures, TLS, favicon",
	Args:  cobra.ExactArgs(1),
	RunE:  runWebTech,
}

var (
	wtTimeout int
	wtSkipTLS bool
)

func init() {
	f := webtechCmd.Flags()
	f.IntVar(&wtTimeout, "timeout", 10, "Request timeout (seconds)")
	f.BoolVar(&wtSkipTLS, "skip-tls", false, "Skip TLS verification")
	rootCmd.AddCommand(webtechCmd)
}

func runWebTech(cmd *cobra.Command, args []string) error {
	url := args[0]
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(url); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("webtech", url, scopeFile, nil)
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
		fmt.Fprintf(os.Stderr, "[spectre] webtech: %s\n", url)
	}

	return webtech.Run(ctx, webtech.Options{
		URL:     url,
		Timeout: time.Duration(wtTimeout) * time.Second,
		SkipTLS: wtSkipTLS,
		Writer:  writer,
	})
}

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/stack"
	"github.com/spf13/cobra"
)

var stackCmd = &cobra.Command{
	Use:   "stack [url]",
	Short: "Technology stack detection — framework versions, hosting/CDN, cloud provider, DB hints, exposed CI/CD config",
	Args:  cobra.ExactArgs(1),
	RunE:  runStack,
}

var (
	stackTimeout          int
	stackSkipTLS          bool
	stackCheckMetadata    bool
	stackCheckFirebase    bool
)

func init() {
	f := stackCmd.Flags()
	f.IntVar(&stackTimeout, "timeout", 10, "Request timeout (seconds)")
	f.BoolVar(&stackSkipTLS, "skip-tls", false, "Skip TLS verification")
	f.BoolVar(&stackCheckMetadata, "check-metadata", false, "Also probe for misconfigured cloud-metadata SSRF exposure (active test — authorized targets only)")
	f.BoolVar(&stackCheckFirebase, "check-firebase", false, "Also probe for Firebase misconfiguration: init.json exposure + unauthenticated Firestore/Realtime DB/Storage access (active test — authorized targets only)")
	rootCmd.AddCommand(stackCmd)
}

func runStack(cmd *cobra.Command, args []string) error {
	url := args[0]
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(url); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("stack", url, scopeFile, nil)
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
		fmt.Fprintf(os.Stderr, "[spectre] stack: %s\n", url)
		if stackCheckMetadata {
			fmt.Fprintf(os.Stderr, "[spectre] stack: --check-metadata enabled — active SSRF probe, authorized targets only\n")
		}
		if stackCheckFirebase {
			fmt.Fprintf(os.Stderr, "[spectre] stack: --check-firebase enabled — active Firebase misconfiguration probe, authorized targets only\n")
		}
	}

	return stack.Run(ctx, stack.Options{
		URL:           url,
		Timeout:       time.Duration(stackTimeout) * time.Second,
		SkipTLS:       stackSkipTLS,
		CheckMetadata: stackCheckMetadata,
		CheckFirebase: stackCheckFirebase,
		Writer:        writer,
	})
}

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/breach"
	"github.com/spectre-tool/spectre/internal/output"
)

var breachCmd = &cobra.Command{
	Use:   "breach [domain-or-email]",
	Short: "Breach/leak exposure check — paste-site scraping + bring-your-own-key breach APIs",
	Args:  cobra.ExactArgs(1),
	RunE:  runBreach,
}

var (
	brTimeout        int
	brRate           float64
	brSkipPaste      bool
	brHIBPKey        string
	brDehashedEmail  string
	brDehashedAPIKey string
)

func init() {
	f := breachCmd.Flags()
	f.IntVar(&brTimeout, "timeout", 15, "Request timeout (seconds)")
	f.Float64Var(&brRate, "rate", 2, "Requests per second against provider APIs")
	f.BoolVar(&brSkipPaste, "skip-paste", false, "Skip the free Pastebin scraper")
	f.StringVar(&brHIBPKey, "hibp-key", "", "HaveIBeenPwned API key (https://haveibeenpwned.com/API/Key)")
	f.StringVar(&brDehashedEmail, "dehashed-email", "", "DeHashed account email")
	f.StringVar(&brDehashedAPIKey, "dehashed-key", "", "DeHashed API key")
	rootCmd.AddCommand(breachCmd)
}

func runBreach(cmd *cobra.Command, args []string) error {
	query := args[0]
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(query); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("breach", query, scopeFile, nil)
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
		fmt.Fprintf(os.Stderr, "[spectre] breach: %s\n", query)
	}

	skipped, err := breach.Run(ctx, breach.Options{
		Query:          query,
		HIBPAPIKey:     brHIBPKey,
		DehashedEmail:  brDehashedEmail,
		DehashedAPIKey: brDehashedAPIKey,
		SkipPaste:      brSkipPaste,
		Timeout:        time.Duration(brTimeout) * time.Second,
		RatePerSec:     brRate,
		Writer:         writer,
	})
	if err != nil {
		return err
	}

	if !silent {
		for _, s := range skipped {
			fmt.Fprintf(os.Stderr, "[spectre] breach: skipped %s\n", s)
		}
	}
	return nil
}

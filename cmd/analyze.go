package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spectre-tool/spectre/internal/analyze"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [target]",
	Short: "Static pattern-based vulnerability scan — DOM XSS, auth bypass, SQLi over JS/HTML/ASPX source",
	Args:  cobra.ExactArgs(1),
	Example: `  spectre analyze ./app.js
  spectre analyze ./src/
  spectre analyze targets.txt --categories dom-xss,sqli`,
	RunE: runAnalyze,
}

var (
	analyzeTimeout       int
	analyzeSkipTLS       bool
	analyzeConcurrency   int
	analyzeMaxFileMB     int
	analyzeCategories    string
	analyzeMinConfidence int
)

func init() {
	f := analyzeCmd.Flags()
	f.IntVar(&analyzeTimeout, "timeout", 10, "Request timeout for URL entries (seconds)")
	f.BoolVar(&analyzeSkipTLS, "skip-tls", false, "Skip TLS verification (URL entries only)")
	f.IntVarP(&analyzeConcurrency, "concurrency", "c", 8, "Concurrent file/URL scans")
	f.IntVar(&analyzeMaxFileMB, "max-file-size", 10, "Per-file/per-URL read cap in MB")
	f.StringVar(&analyzeCategories, "categories", "dom-xss,auth-bypass,sqli", "Comma list of detection categories to enable")
	f.IntVar(&analyzeMinConfidence, "min-confidence", 0, "Suppress findings below this confidence")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Scope checking is host/IP-oriented; local file/directory/list targets
	// have no network target to authorize against, so the scope check only
	// applies when the target itself looks like a URL.
	if globalScope != nil && strings.Contains(target, "://") {
		if ok, reason := globalScope.Authorized(target); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("analyze", target, scopeFile, map[string]any{
			"categories": analyzeCategories,
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

	writer := output.NewWriter(outputFmt, dest, noColor)
	defer writer.Close()

	if !silent {
		fmt.Fprintf(os.Stderr, "[spectre] analyze: %s\n", target)
	}

	var categories []string
	if analyzeCategories != "" {
		categories = strings.Split(analyzeCategories, ",")
	}

	return analyze.Run(ctx, analyze.Options{
		Target:        target,
		Timeout:       time.Duration(analyzeTimeout) * time.Second,
		SkipTLS:       analyzeSkipTLS,
		MaxFileSize:   int64(analyzeMaxFileMB) * 1024 * 1024,
		Concurrency:   analyzeConcurrency,
		Categories:    categories,
		MinConfidence: analyzeMinConfidence,
		EmbeddedFS:    embeddedFS,
		Writer:        writer,
	})
}

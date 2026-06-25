package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/subdomain"
	"github.com/spectre-tool/spectre/internal/wordlists"
)

var subdomainCmd = &cobra.Command{
	Use:   "subdomain",
	Short: "Subdomain enumeration — passive sources, brute force, and coverage maximizers",
	Example: `  spectre subdomain -d example.com --passive
  spectre subdomain -d example.com --all -w subdomain:medium -f json -o subs.json
  spectre subdomain -d example.com --fast   # head-to-head vs assetfinder`,
	RunE: runSubdomain,
}

var (
	subDomain       string
	subWordlist     string
	subConcurrency  int
	subTimeout      int
	subRate         float64
	subPassive      bool
	subBrute        bool
	subAll          bool
	subFast         bool
	subResolvers    string
	subSources      string
	subSkipWildcard bool
	subProxies      string
)

func init() {
	f := subdomainCmd.Flags()
	f.StringVarP(&subDomain, "domain", "d", "", "Target domain (required)")
	f.StringVarP(&subWordlist, "wordlist", "w", "", "Wordlist path or group (e.g. subdomain:medium)")
	f.IntVarP(&subConcurrency, "concurrency", "c", 50, "Concurrent DNS workers")
	f.IntVarP(&subTimeout, "timeout", "t", 10, "Per-request timeout (seconds)")
	f.Float64VarP(&subRate, "rate", "r", 100, "Requests per second")
	f.BoolVarP(&subPassive, "passive", "p", false, "Passive sources only (no brute force)")
	f.BoolVarP(&subBrute, "brute", "b", false, "Brute force only (no passive sources)")
	f.BoolVar(&subAll, "all", false, "All modes: passive + brute + permute + archive + OSINT")
	f.BoolVar(&subFast, "fast", false, "Fast passive-only streaming mode (no resolve, assetfinder-parity)")
	f.StringVar(&subResolvers, "resolvers", "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53", "DNS resolvers (comma-separated ip:port)")
	f.StringVar(&subSources, "sources", "", "Passive sources to use (comma-separated: crtsh,hackertarget,alienvault,rapiddns,certspotter)")
	f.BoolVar(&subSkipWildcard, "skip-wildcard", false, "Skip wildcard DNS detection")
	f.StringVar(&subProxies, "proxies", "", "Proxy list file for anti-block rotation")
	_ = subdomainCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(subdomainCmd)
}

func runSubdomain(cmd *cobra.Command, args []string) error {
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(subDomain); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("subdomain", subDomain, scopeFile, map[string]any{
			"passive": subPassive, "brute": subBrute, "all": subAll, "fast": subFast,
		})
		defer globalAudit.Close()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Output destination
	dest := os.Stdout
	var fileOut *os.File
	if outputFile != "" {
		var err error
		fileOut, err = os.Create(outputFile)
		if err != nil {
			return err
		}
		defer fileOut.Close()
		dest = fileOut
	}

	if !silent {
		fmt.Fprintf(os.Stderr, "[spectre] subdomain enumeration: %s\n", subDomain)
	}

	// Fast mode: streaming head-to-head vs assetfinder
	if subFast {
		n, err := subdomain.FastModeRun(ctx, subdomain.Options{
			Domain:    subDomain,
			Resolvers: parseComma(subResolvers),
			Sources:   parseComma(subSources),
			Timeout:   time.Duration(subTimeout) * time.Second,
			RatePerSec: subRate,
		}, dest)
		if err != nil {
			return err
		}
		if !silent {
			fmt.Fprintf(os.Stderr, "\n[spectre] found %d subdomains (fast mode)\n", n)
		}
		return nil
	}

	writer := output.NewWriter(outputFmt, dest, noColor)

	cat, err := wordlists.LoadCatalog()
	if err != nil {
		return err
	}

	opts := subdomain.Options{
		Domain:       subDomain,
		WordlistSpec: subWordlist,
		Concurrency:  subConcurrency,
		Timeout:      time.Duration(subTimeout) * time.Second,
		RatePerSec:   subRate,
		PassiveOnly:  subPassive,
		BruteOnly:    subBrute,
		AllModes:     subAll,
		SkipWildcard: subSkipWildcard,
		Resolvers:    parseComma(subResolvers),
		Sources:      parseComma(subSources),
		ProxyFile:    subProxies,
		Writer:       writer,
		Catalog:      cat,
	}

	summary, err := subdomain.Run(ctx, opts)
	if err != nil {
		return err
	}
	_ = writer.Flush()

	if !silent {
		fmt.Fprintf(os.Stderr, "\n[spectre] found %d subdomains (%d passive, %d brute) in %s\n",
			summary.Total, summary.Passive, summary.Brute, summary.Duration.Round(time.Millisecond))
	}
	return nil
}

func parseComma(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

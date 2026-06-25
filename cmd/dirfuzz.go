package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/dirfuzz"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
	"github.com/spectre-tool/spectre/internal/wordlists"
)

var dirfuzzCmd = &cobra.Command{
	Use:   "dirfuzz",
	Short: "Directory and file fuzzing with recursive descent and WAF evasion",
	Example: `  spectre dirfuzz -u https://example.com -x php,html
  spectre dirfuzz -u https://example.com -w directory:large --recursive --depth 3
  spectre dirfuzz -u https://example.com --waf-evasion --status-filter 200,301,403`,
	RunE: runDirFuzz,
}

var (
	dfURL          string
	dfWordlist     string
	dfConcurrency  int
	dfTimeout      int
	dfRate         float64
	dfExtensions   string
	dfMethod       string
	dfStatusFilter string
	dfStatusExcl   string
	dfSizeExcl     string
	dfBodyExcl     string
	dfSkipTLS      bool
	dfFollowRedir  bool
	dfHeaders      string
	dfCookies      string
	dfWafEvasion   bool
	dfRecursive    bool
	dfDepth        int
	dfProxies      string
)

func init() {
	f := dirfuzzCmd.Flags()
	f.StringVarP(&dfURL, "url", "u", "", "Target URL (required)")
	f.StringVarP(&dfWordlist, "wordlist", "w", "", "Wordlist path or group (e.g. directory:medium)")
	f.IntVarP(&dfConcurrency, "concurrency", "c", 50, "Concurrent workers")
	f.IntVarP(&dfTimeout, "timeout", "t", 10, "Per-request timeout (seconds)")
	f.Float64VarP(&dfRate, "rate", "r", 150, "Requests per second")
	f.StringVarP(&dfExtensions, "extensions", "x", "", "Extensions to try: php,html,txt")
	f.StringVarP(&dfMethod, "method", "m", "GET", "HTTP method")
	f.StringVar(&dfStatusFilter, "status-filter", "200,204,301,302,307,401,403", "Show only these status codes")
	f.StringVar(&dfStatusExcl, "status-exclude", "", "Exclude these status codes")
	f.StringVar(&dfSizeExcl, "size-exclude", "", "Exclude by response size (bytes)")
	f.StringVar(&dfBodyExcl, "body-exclude", "", "Exclude if response body contains this string")
	f.BoolVar(&dfSkipTLS, "skip-tls", false, "Skip TLS certificate verification")
	f.BoolVar(&dfFollowRedir, "follow-redir", false, "Follow HTTP redirects")
	f.StringVar(&dfHeaders, "headers", "", "Extra headers: Key:Value,Key2:Value2")
	f.StringVar(&dfCookies, "cookies", "", "Cookie header value")
	f.BoolVar(&dfWafEvasion, "waf-evasion", false, "Enable WAF bypass headers and path mutations")
	f.BoolVar(&dfRecursive, "recursive", false, "Recursively fuzz found directories")
	f.IntVar(&dfDepth, "depth", 3, "Maximum recursion depth")
	f.StringVar(&dfProxies, "proxies", "", "Proxy list file")
	_ = dirfuzzCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(dirfuzzCmd)
}

func runDirFuzz(cmd *cobra.Command, args []string) error {
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(dfURL); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("dirfuzz", dfURL, scopeFile, map[string]any{
			"wordlist": dfWordlist, "recursive": dfRecursive, "waf": dfWafEvasion,
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
		fmt.Fprintf(os.Stderr, "[spectre] dirfuzz: %s\n", dfURL)
	}

	writer := output.NewWriter(outputFmt, dest, noColor)

	// Parse status filters
	statusFilter := parseIntList(dfStatusFilter)
	statusExcl := parseIntList(dfStatusExcl)
	sizeExcl := parseInt64List(dfSizeExcl)

	// Parse extra headers
	extraHeaders := parseHeaders(dfHeaders)

	// Load wordlist
	var wordCh <-chan string
	if dfWordlist != "" {
		cat, err := wordlists.LoadCatalog()
		if err != nil {
			return err
		}
		resolver := wordlists.NewResolver(cat, embeddedFS)
		ch, _, err := resolver.Resolve(dfWordlist)
		if err != nil {
			return err
		}
		wordCh = ch
	} else {
		loader := utils.NewWordlistLoader(embeddedFS)
		ch, err := loader.Load("", "directories.txt")
		if err != nil {
			return err
		}
		wordCh = ch
	}

	opts := dirfuzz.Options{
		URL:          dfURL,
		WordlistSpec: dfWordlist,
		Concurrency:  dfConcurrency,
		Timeout:      time.Duration(dfTimeout) * time.Second,
		RatePerSec:   dfRate,
		Extensions:   parseComma(dfExtensions),
		Method:       dfMethod,
		StatusFilter: statusFilter,
		StatusExcl:   statusExcl,
		SizeExcl:     sizeExcl,
		BodyExcl:     dfBodyExcl,
		SkipTLS:      dfSkipTLS,
		FollowRedirs: dfFollowRedir,
		ExtraHeaders: extraHeaders,
		Cookies:      dfCookies,
		WafEvasion:   dfWafEvasion,
		Recursive:    dfRecursive,
		MaxDepth:     dfDepth,
		ProxyFile:    dfProxies,
		WordCh:       wordCh,
		Writer:       writer,
	}

	summary, err := dirfuzz.Run(ctx, opts)
	if err != nil {
		return err
	}
	_ = writer.Flush()

	if !silent {
		fmt.Fprintf(os.Stderr, "\n[spectre] found %d paths (%d probed) in %s\n",
			summary.Found, summary.Total, summary.Duration.Round(time.Millisecond))
	}
	return nil
}

func parseIntList(s string) []int {
	if s == "" {
		return nil
	}
	var result []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if n, err := strconv.Atoi(p); err == nil {
			result = append(result, n)
		}
	}
	return result
}

func parseInt64List(s string) []int64 {
	if s == "" {
		return nil
	}
	var result []int64
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if n, err := strconv.ParseInt(p, 10, 64); err == nil {
			result = append(result, n)
		}
	}
	return result
}

func parseHeaders(s string) http.Header {
	if s == "" {
		return nil
	}
	h := make(http.Header)
	for _, pair := range strings.Split(s, ",") {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			h.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	return h
}

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spectre-tool/spectre/internal/crawl"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spf13/cobra"
)

var crawlCmd = &cobra.Command{
	Use:   "crawl [url]",
	Short: "Crawl same-origin pages + linked JS/CSS, extract endpoints/secrets/source-map refs",
	Args:  cobra.ExactArgs(1),
	Example: `  spectre crawl https://example.com
  spectre crawl https://example.com --depth 3 --max-pages 200
  spectre crawl https://example.com --same-origin=false -f json -o crawl.json`,
	RunE: runCrawl,
}

var (
	crawlTimeout     int
	crawlSkipTLS     bool
	crawlConcurrency int
	crawlMaxAssetMB  int
	crawlDepth       int
	crawlMaxPages    int
	crawlSameOrigin  bool
	crawlHeaders     string
	crawlCookies     string
)

func init() {
	f := crawlCmd.Flags()
	f.IntVar(&crawlTimeout, "timeout", 10, "Request timeout (seconds)")
	f.BoolVar(&crawlSkipTLS, "skip-tls", false, "Skip TLS verification")
	f.IntVarP(&crawlConcurrency, "concurrency", "c", 10, "Concurrent page/asset fetches")
	f.IntVar(&crawlMaxAssetMB, "max-asset-size", 5, "Per-asset read cap in MB")
	f.IntVar(&crawlDepth, "depth", 2, "Max same-origin link-following depth from the seed page")
	f.IntVar(&crawlMaxPages, "max-pages", 100, "Hard cap on total pages visited")
	f.BoolVar(&crawlSameOrigin, "same-origin", true, "Restrict link-following to the seed URL's host")
	f.StringVar(&crawlHeaders, "headers", "", "Extra headers: Key:Value,Key2:Value2")
	f.StringVar(&crawlCookies, "cookies", "", "Cookie header value")
	rootCmd.AddCommand(crawlCmd)
}

func runCrawl(cmd *cobra.Command, args []string) error {
	url := args[0]
	if globalScope != nil {
		if ok, reason := globalScope.Authorized(url); !ok {
			return fmt.Errorf("out of scope: %s", reason)
		}
	}
	if globalAudit != nil {
		_ = globalAudit.Log("crawl", url, scopeFile, map[string]any{
			"depth": crawlDepth, "max_pages": crawlMaxPages, "same_origin": crawlSameOrigin,
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

	if !crawlSameOrigin && !silent {
		fmt.Fprintln(os.Stderr, "[warn] --same-origin=false: crawl will follow links to other domains too")
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "[spectre] crawl: %s (depth=%d, max-pages=%d)\n", url, crawlDepth, crawlMaxPages)
	}

	return crawl.Run(ctx, crawl.Options{
		URL:          url,
		Timeout:      time.Duration(crawlTimeout) * time.Second,
		SkipTLS:      crawlSkipTLS,
		Concurrency:  crawlConcurrency,
		MaxAssetSize: int64(crawlMaxAssetMB) * 1024 * 1024,
		Depth:        crawlDepth,
		MaxPages:     crawlMaxPages,
		SameOrigin:   crawlSameOrigin,
		Headers:      parseHeaders(crawlHeaders),
		Cookies:      crawlCookies,
		Writer:       writer,
	})
}

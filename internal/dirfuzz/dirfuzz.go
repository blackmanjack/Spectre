package dirfuzz

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options holds all configuration for directory fuzzing.
type Options struct {
	URL          string
	WordlistSpec string
	Concurrency  int
	Timeout      time.Duration
	RatePerSec   float64
	Extensions   []string
	Method       string
	StatusFilter []int
	StatusExcl   []int
	SizeExcl     []int64
	BodyExcl     string
	SkipTLS      bool
	FollowRedirs bool
	ExtraHeaders http.Header
	Cookies      string
	WafEvasion   bool
	Recursive    bool
	MaxDepth     int
	ProxyFile    string
	WordCh       <-chan string // pre-built channel (used when resolver sets it)
	Writer       output.Writer
}

// Summary holds scan statistics.
type Summary struct {
	Total    int64
	Found    int64
	Duration time.Duration
}

// Run executes directory fuzzing.
func Run(ctx context.Context, opts Options) (Summary, error) {
	start := time.Now()
	var summary Summary

	client := utils.NewClient(utils.ClientConfig{
		Timeout:       opts.Timeout,
		SkipTLSVerify: opts.SkipTLS,
		FollowRedirs:  opts.FollowRedirs,
		Cookies:       opts.Cookies,
		ExtraHeaders:  opts.ExtraHeaders,
	})

	rl := utils.NewRateLimiter(opts.RatePerSec)

	// Auto-calibrate soft-404
	cfg := FilterConfig{
		StatusFilter: opts.StatusFilter,
		StatusExcl:   opts.StatusExcl,
		SizeExcl:     opts.SizeExcl,
		BodyExcl:     opts.BodyExcl,
	}
	softBody, softSize, err := calibrateSoft404(ctx, client, opts.URL)
	if err == nil && len(softBody) > 0 {
		fmt.Fprintf(os.Stderr, "[warn] Soft-404 detected (size=%d), auto-calibrating filter\n", softSize)
		cfg.Soft404Body = softBody
		cfg.Soft404Size = softSize
	}

	wordCh := opts.WordCh

	out := make(chan output.Result, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range out {
			_ = opts.Writer.Write(r)
			atomic.AddInt64(&summary.Found, 1)
		}
	}()

	// Track found directories for recursive fuzzing
	var foundDirs []string
	var dirMu sync.Mutex

	fuzz(ctx, opts.URL, wordCh, opts, client, rl, cfg, out, func(path string) {
		dirMu.Lock()
		foundDirs = append(foundDirs, path)
		dirMu.Unlock()
		atomic.AddInt64(&summary.Total, 1)
	}, &summary.Total)

	// Recursive descent
	if opts.Recursive && opts.MaxDepth > 0 {
		depth := 1
		for depth <= opts.MaxDepth && len(foundDirs) > 0 {
			var nextDirs []string
			for _, dir := range foundDirs {
				subURL := strings.TrimRight(opts.URL, "/") + dir
				// Reload wordlist for each subdirectory
				if opts.WordCh == nil {
					wl := utils.NewWordlistLoader(nil)
					subCh, err := wl.Load("", "directories.txt")
					if err != nil {
						continue
					}
					var subdirs []string
					fuzz(ctx, subURL, subCh, opts, client, rl, cfg, out, func(path string) {
						subdirs = append(subdirs, dir+path)
					}, &summary.Total)
					nextDirs = append(nextDirs, subdirs...)
				}
			}
			foundDirs = nextDirs
			depth++
		}
	}

	close(out)
	<-done
	summary.Duration = time.Since(start)
	return summary, nil
}

// fuzz runs the core fuzzing loop for one URL base.
func fuzz(
	ctx context.Context,
	baseURL string,
	wordCh <-chan string,
	opts Options,
	client *http.Client,
	rl *utils.RateLimiter,
	cfg FilterConfig,
	out chan<- output.Result,
	onDir func(path string),
	totalCounter *int64,
) {
	work := make(chan string, opts.Concurrency*2)

	go func() {
		defer close(work)
		for word := range wordCh {
			for _, path := range buildPaths(word, opts.Extensions) {
				select {
				case work <- path:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case path, ok := <-work:
					if !ok {
						return
					}
					if err := rl.Wait(ctx); err != nil {
						return
					}
					headers := opts.ExtraHeaders
					if opts.WafEvasion {
						headers = wafHeaders(headers)
					}
					r, err := probe(ctx, client, method, baseURL, path, headers)
					if err != nil {
						continue
					}
					atomic.AddInt64(totalCounter, 1)
					if !ShouldShow(r, cfg) {
						continue
					}
					out <- output.Result{
						Type:   output.TypeDirFuzz,
						Value:  path,
						Status: r.Status,
						Size:   r.Size,
						Words:  r.Words,
						Lines:  r.Lines,
					}
					// Track directories for recursive fuzzing
					if onDir != nil && isDirectory(r) {
						onDir(path)
					}
				}
			}
		}()
	}
	wg.Wait()
}

// isDirectory heuristically determines if a result is a browsable directory.
func isDirectory(r ProbeResult) bool {
	return (r.Status == 200 || r.Status == 301 || r.Status == 302 || r.Status == 403) &&
		!strings.Contains(r.Path, ".")
}

// wafHeaders injects WAF bypass headers into a request header map.
func wafHeaders(base http.Header) http.Header {
	h := base.Clone()
	if h == nil {
		h = make(http.Header)
	}
	h.Set("X-Forwarded-For", "127.0.0.1")
	h.Set("X-Originating-IP", "127.0.0.1")
	h.Set("X-Remote-IP", "127.0.0.1")
	h.Set("X-Remote-Addr", "127.0.0.1")
	h.Set("X-Original-URL", "/")
	h.Set("X-Rewrite-URL", "/")
	h.Set("X-Forwarded-Host", "localhost")
	h.Set("X-Host", "localhost")
	return h
}

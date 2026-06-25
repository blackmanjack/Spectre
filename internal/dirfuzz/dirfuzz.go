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

	// Cache words once for reuse across recursion depths. Re-opening and
	// re-scanning the wordlist file for every discovered directory turns a
	// single-pass scan into O(dirs * wordlist_size) I/O; with large wordlists
	// (Assetnote-class, multi-MB) that defeats the "faster than alternatives"
	// goal. We pay one read + memory cost up front instead.
	var cachedWords []string
	if opts.Recursive && opts.MaxDepth > 0 {
		for w := range wordCh {
			cachedWords = append(cachedWords, w)
		}
		wordCh = sliceToChannel(cachedWords)
	}

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

	// Recursive descent — reuses cachedWords instead of re-reading the wordlist
	// file per directory (see comment above).
	if opts.Recursive && opts.MaxDepth > 0 {
		depth := 1
		for depth <= opts.MaxDepth && len(foundDirs) > 0 {
			var nextDirs []string
			for _, dir := range foundDirs {
				safeDir, ok := sanitizeDirPath(dir)
				if !ok {
					// Reject path-traversal or otherwise unsafe directory names
					// surfaced by the wordlist (e.g. "/../admin") rather than
					// folding them into the recursive URL.
					fmt.Fprintf(os.Stderr, "[warn] skipping unsafe recursive path %q\n", dir)
					continue
				}
				subURL := strings.TrimRight(opts.URL, "/") + safeDir
				var subdirs []string
				fuzz(ctx, subURL, sliceToChannel(cachedWords), opts, client, rl, cfg, out, func(path string) {
					subdirs = append(subdirs, safeDir+path)
				}, &summary.Total)
				nextDirs = append(nextDirs, subdirs...)
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

// sliceToChannel re-streams a cached word slice as a channel so fuzz() can
// consume it the same way it consumes a freshly loaded wordlist.
func sliceToChannel(words []string) <-chan string {
	ch := make(chan string, len(words))
	for _, w := range words {
		ch <- w
	}
	close(ch)
	return ch
}

// sanitizeDirPath rejects directory paths that could escape the discovered
// directory's URL scope (path traversal, query/fragment injection) before
// they are concatenated into a recursive fuzz URL. Returns the cleaned path
// and false if the input should be skipped entirely.
func sanitizeDirPath(dir string) (string, bool) {
	if dir == "" || !strings.HasPrefix(dir, "/") {
		return "", false
	}
	if strings.Contains(dir, "..") || strings.ContainsAny(dir, "?#") {
		return "", false
	}
	// Collapse accidental double slashes from prior concatenation.
	for strings.Contains(dir, "//") {
		dir = strings.ReplaceAll(dir, "//", "/")
	}
	return dir, true
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

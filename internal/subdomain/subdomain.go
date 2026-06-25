package subdomain

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/subdomain/sources"
	"github.com/spectre-tool/spectre/internal/utils"
	wl "github.com/spectre-tool/spectre/internal/wordlists"
)

// Options holds all user-supplied flags for subdomain enumeration.
type Options struct {
	Domain       string
	WordlistSpec string   // path or group spec for brute force
	Concurrency  int
	Timeout      time.Duration
	RatePerSec   float64
	PassiveOnly  bool
	BruteOnly    bool
	AllModes     bool     // passive + brute + all enrichers
	FastMode     bool     // passive only, streaming, no resolve — head-to-head vs assetfinder
	Resolvers    []string
	Sources      []string // which passive sources to enable
	SkipWildcard bool
	ProxyFile    string

	Writer  output.Writer
	Catalog *wl.Catalog
}

// Summary holds scan statistics.
type Summary struct {
	Total    int
	Passive  int
	Brute    int
	Duration time.Duration
}

// Run executes subdomain enumeration according to Options.
func Run(ctx context.Context, opts Options) (Summary, error) {
	start := time.Now()
	var summary Summary

	pool := utils.NewResolverPool(opts.Resolvers)
	rl := utils.NewRateLimiter(opts.RatePerSec)

	var proxyPool *utils.ProxyPool
	if opts.ProxyFile != "" {
		var err error
		proxyPool, err = utils.LoadProxyFile(opts.ProxyFile)
		if err != nil {
			return summary, err
		}
	} else {
		proxyPool = utils.NewProxyPool(nil)
	}

	client := proxyPool.NewHTTPClient(utils.ClientConfig{
		Timeout: opts.Timeout,
	})
	if proxyPool.IsDisabled() {
		client = utils.NewClient(utils.ClientConfig{Timeout: opts.Timeout})
	}

	seen := &sync.Map{}
	out := make(chan output.Result, 128)

	// Sink: write results. Closing `out` (deferred below) always unblocks this
	// goroutine, even if Run returns early on an error — otherwise the sink
	// would hang forever on `range out` and the process could not exit cleanly.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range out {
			_ = opts.Writer.Write(r)
			summary.Total++
			if r.Source == "brute" {
				summary.Brute++
			} else {
				summary.Passive++
			}
		}
	}()
	defer func() {
		close(out)
		<-done
	}()

	srcs := buildSources(opts.Sources)

	if !opts.BruteOnly {
		RunPassive(ctx, opts.Domain, srcs, client, rl, pool, seen, out)
	}

	if !opts.PassiveOnly && !opts.FastMode {
		// Wildcard detection
		var wc *WildcardResult
		if !opts.SkipWildcard {
			detector := NewWildcardDetector(pool)
			var err error
			wc, err = detector.Detect(ctx, opts.Domain)
			if err != nil {
				return summary, err
			}
		}

		// Load wordlist
		loader := wl.NewResolver(opts.Catalog, nil)
		spec := opts.WordlistSpec
		if spec == "" {
			spec = "subdomains.txt"
		}
		wordCh, _, err := loader.Resolve(spec)
		if err != nil {
			// Fall back to embedded
			wldr := utils.NewWordlistLoader(nil)
			wordCh, err = wldr.Load("", "subdomains.txt")
			if err != nil {
				return summary, err
			}
		}

		RunBruteForce(ctx, BruteOptions{
			Domain:      opts.Domain,
			WordlistCh:  wordCh,
			Pool:        pool,
			RateLimit:   rl,
			Concurrency: opts.Concurrency,
			Wildcard:    wc,
			Seen:        seen,
		}, out)
	}

	summary.Duration = time.Since(start)
	return summary, nil
}

func buildSources(enabled []string) []Source {
	all := map[string]Source{
		"crtsh":       &sources.CrtSH{},
		"hackertarget": &sources.HackerTarget{},
		"alienvault":  &sources.AlienVault{},
		"rapiddns":    &sources.RapidDNS{},
		"certspotter": &sources.CertSpotter{},
	}
	if len(enabled) == 0 {
		// Default: all
		result := make([]Source, 0, len(all))
		for _, s := range all {
			result = append(result, s)
		}
		return result
	}
	var result []Source
	for _, name := range enabled {
		name = strings.ToLower(strings.TrimSpace(name))
		if s, ok := all[name]; ok {
			result = append(result, s)
		}
	}
	return result
}

// FastModeRun is the --fast mode: passive only, streaming, no resolve.
// Apple-to-apple comparison with assetfinder.
func FastModeRun(ctx context.Context, opts Options, dest io.Writer) (int, error) {
	pool := utils.NewResolverPool(opts.Resolvers)
	rl := utils.NewRateLimiter(opts.RatePerSec)
	client := utils.NewClient(utils.ClientConfig{
		Timeout: opts.Timeout,
	})

	srcs := buildSources(opts.Sources)
	seen := &sync.Map{}
	out := make(chan output.Result, 256)
	count := 0

	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range out {
			// Fast mode: print raw, no color, no resolve
			_, _ = io.WriteString(dest, r.Value+"\n")
			count++
		}
	}()

	RunPassive(ctx, opts.Domain, srcs, client, rl, pool, seen, out)
	close(out)
	<-done
	return count, nil
}

// noopWriter satisfies io.Writer for when we don't want file output.
type noopWriter struct{}

func (n *noopWriter) Write(b []byte) (int, error) { return len(b), nil }

var _ io.Writer = (*noopWriter)(nil)

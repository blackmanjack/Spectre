package subdomain

import (
	"context"
	"net/http"
	"sync"

	"github.com/spectre-tool/spectre/internal/enrich"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// EnrichOptions configures the coverage maximizers triggered by --all.
type EnrichOptions struct {
	Domain         string
	GitHubToken    string // optional; GitHub search works unauthenticated at a lower rate limit
	RecursionDepth int    // bound on permutation recursion (default 2 if 0)
}

// RunEnrich fans out to every coverage maximizer (permutation, recursive
// enumeration, Wayback/CommonCrawl archive mining, GitHub code search, search
// engine dorking), resolves each candidate, deduplicates against the shared
// `seen` map, and streams confirmed-live results to out.
//
// This is what `subdomain --all` actually invokes, on top of the base
// passive+brute results already collected in `seen`.
func RunEnrich(
	ctx context.Context,
	opts EnrichOptions,
	client *http.Client,
	pool *utils.ResolverPool,
	rl *utils.RateLimiter,
	seen *sync.Map,
	out chan<- output.Result,
) {
	depth := opts.RecursionDepth
	if depth <= 0 {
		depth = 2
	}

	// Snapshot what passive+brute already found, to seed permutation at depth 0.
	var baseline []string
	seen.Range(func(k, v any) bool {
		if name, ok := k.(string); ok {
			baseline = append(baseline, name)
		}
		return true
	})

	// resolveAndEmit resolves one candidate, dedups it, and on success queues
	// it for further recursive permutation (up to depth). Returns true if the
	// candidate was newly confirmed live.
	type queued struct {
		name  string
		depth int
	}
	var queue []queued
	var queueMu sync.Mutex

	resolveAndEmit := func(name, source string, atDepth int) bool {
		if _, already := seen.LoadOrStore(name, true); already {
			return false
		}
		if err := rl.Wait(ctx); err != nil {
			return false
		}
		ips, err := pool.ResolveHost(ctx, name)
		if err != nil || len(ips) == 0 {
			return false // not live — discard rather than report an unresolvable name
		}
		select {
		case out <- output.Result{Type: output.TypeSubdomain, Value: name, Source: source, IPs: ips}:
		case <-ctx.Done():
			return false
		}
		if atDepth < depth {
			queueMu.Lock()
			queue = append(queue, queued{name: name, depth: atDepth + 1})
			queueMu.Unlock()
		}
		return true
	}

	// --- Phase 1: independent archive/OSINT sources, fanned in concurrently ---
	merge := make(chan namedSub, 256)
	var wg sync.WaitGroup
	fanIn := func(source string, ch <-chan string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range ch {
				select {
				case merge <- namedSub{name: name, source: source}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	fanIn("wayback", enrich.WaybackURLs(ctx, opts.Domain, client))
	fanIn("commoncrawl", enrich.CommonCrawlURLs(ctx, opts.Domain, client))
	fanIn("github", enrich.GitHubSearch(ctx, opts.Domain, client, opts.GitHubToken))
	fanIn("dork", enrich.SearchEngineDork(ctx, opts.Domain, client))
	if len(baseline) > 0 {
		fanIn("permute", enrich.Permute(ctx, opts.Domain, baseline))
	}
	go func() {
		wg.Wait()
		close(merge)
	}()

	for item := range merge {
		resolveAndEmit(item.name, item.source, 0)
	}

	// --- Phase 2: bounded recursive permutation on newly confirmed names ---
	// Each round permutes only the names queued by the previous round, so
	// recursion depth is enforced rather than re-permuting the whole result
	// set repeatedly.
	for {
		queueMu.Lock()
		round := queue
		queue = nil
		queueMu.Unlock()
		if len(round) == 0 {
			break
		}
		for _, q := range round {
			for sub := range enrich.Permute(ctx, opts.Domain, []string{q.name}) {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resolveAndEmit(sub, "permute-recursive", q.depth)
			}
		}
	}
}

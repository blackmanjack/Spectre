package subdomain

import (
	"context"
	"sync"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// BruteOptions parameterizes the active DNS brute-force phase.
type BruteOptions struct {
	Domain      string
	WordlistCh  <-chan string
	Pool        *utils.ResolverPool
	RateLimit   *utils.RateLimiter
	Concurrency int
	Wildcard    *WildcardResult
	Seen        *sync.Map
}

// RunBruteForce fans Concurrency workers over wordlistCh.
// Each worker: rate.Wait → resolve → wildcard-check → emit to out.
func RunBruteForce(ctx context.Context, opts BruteOptions, out chan<- output.Result) {
	work := make(chan string, opts.Concurrency*2)

	// Feed words into work channel
	go func() {
		defer close(work)
		for word := range opts.WordlistCh {
			select {
			case work <- word:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bruteWorker(ctx, opts, work, out)
		}()
	}
	wg.Wait()
}

func bruteWorker(ctx context.Context, opts BruteOptions, work <-chan string, out chan<- output.Result) {
	for {
		select {
		case <-ctx.Done():
			return
		case word, ok := <-work:
			if !ok {
				return
			}
			if err := opts.RateLimit.Wait(ctx); err != nil {
				return
			}
			fqdn := word + "." + opts.Domain
			ips, err := opts.Pool.Resolve(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				continue
			}
			// Wildcard filter
			if opts.Wildcard != nil && opts.Wildcard.IsWildcardMatch(ips) {
				continue
			}
			// Dedup
			if _, already := opts.Seen.LoadOrStore(fqdn, true); already {
				continue
			}
			ipStrs := make([]string, len(ips))
			for i, ip := range ips {
				ipStrs[i] = ip.String()
			}
			select {
			case out <- output.Result{
				Type:   output.TypeSubdomain,
				Value:  fqdn,
				Source: "brute",
				IPs:    ipStrs,
			}:
			case <-ctx.Done():
				return
			}
		}
	}
}

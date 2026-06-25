package subdomain

import (
	"context"
	"net/http"
	"sync"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Source is implemented by each passive DNS provider.
type Source interface {
	Name() string
	Query(ctx context.Context, domain string, client *http.Client) (<-chan string, error)
}

// RunPassive fans out to all enabled sources concurrently, deduplicates via seen map,
// resolves each found subdomain, and sends results to out.
// Source errors are isolated — other sources continue.
func RunPassive(
	ctx context.Context,
	domain string,
	sources []Source,
	client *http.Client,
	rl *utils.RateLimiter,
	pool *utils.ResolverPool,
	seen *sync.Map,
	out chan<- output.Result,
) {
	var wg sync.WaitGroup
	merge := make(chan namedSub, 256)

	for _, src := range sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			if err := rl.Wait(ctx); err != nil {
				return
			}
			ch, err := s.Query(ctx, domain, client)
			if err != nil {
				return
			}
			for sub := range ch {
				select {
				case merge <- namedSub{name: sub, source: s.Name()}:
				case <-ctx.Done():
					return
				}
			}
		}(src)
	}

	go func() {
		wg.Wait()
		close(merge)
	}()

	for item := range merge {
		if _, already := seen.LoadOrStore(item.name, true); already {
			continue
		}
		// Resolve to confirm liveness and get IPs
		ips, _ := pool.ResolveHost(ctx, item.name)
		select {
		case out <- output.Result{
			Type:   output.TypeSubdomain,
			Value:  item.name,
			Source: item.source,
			IPs:    ips,
		}:
		case <-ctx.Done():
			return
		}
	}
}

type namedSub struct {
	name   string
	source string
}

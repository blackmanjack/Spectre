// Package crawl fetches a target site's HTML and same-origin linked pages
// (bounded BFS), pulls every linked JS/CSS asset, and extracts endpoints,
// secrets, and source-map references from everything fetched — the same
// workflow as browser extensions like FindSomething/LinkFinder/SecretFinder,
// run from the command line. No JavaScript is executed; this is a static,
// HTTP-only crawl, so endpoints only revealed after client-side JS runs
// (lazy-loaded routes, dynamically constructed URLs) will not be found.
package crawl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options configures a crawl run.
type Options struct {
	URL          string
	Timeout      time.Duration
	SkipTLS      bool
	Concurrency  int
	MaxAssetSize int64 // bytes; 0 defaults to 5MB
	Depth        int   // BFS link-following depth from the seed page; 0 = seed page only
	MaxPages     int   // hard cap on total pages visited
	SameOrigin   bool  // restrict link-following to the seed URL's host
	Headers      http.Header
	Cookies      string
	Writer       output.Writer
}

type finding struct {
	value      string
	source     string
	confidence int
	extra      string
	size       int64
}

// Run performs a bounded same-origin crawl: BFS over <a href> page links up
// to Depth/MaxPages, fetching every linked JS/CSS asset per page and
// extracting endpoints/secrets/source-map references from each fetched body.
func Run(ctx context.Context, opts Options) error {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.MaxAssetSize <= 0 {
		opts.MaxAssetSize = 5 * 1024 * 1024
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 100
	}

	client := utils.NewClient(utils.ClientConfig{
		Timeout:       opts.Timeout,
		SkipTLSVerify: opts.SkipTLS,
		FollowRedirs:  true,
		MaxRedirects:  5,
		ExtraHeaders:  opts.Headers,
		Cookies:       opts.Cookies,
	})

	emit := func(f finding) {
		_ = opts.Writer.Write(output.Result{
			Type:       output.TypeCrawl,
			Value:      f.value,
			Source:     f.source,
			Confidence: f.confidence,
			Extra:      f.extra,
			Size:       f.size,
			Timestamp:  time.Now(),
		})
	}

	var (
		seenPages    sync.Map // visited/queued page URL -> bool
		seenAssets   sync.Map // fetched asset URL -> bool
		seenFindings sync.Map // finding value -> bool (report each value once)
	)

	type page struct {
		url   string
		depth int
	}

	seed := stripFragment(opts.URL)
	seenPages.Store(seed, true)
	queue := []page{{url: seed, depth: 0}}
	pagesVisited := 0

	var assetWG sync.WaitGroup
	assetSem := make(chan struct{}, opts.Concurrency)

	fetchAsset := func(assetURL, foundOnPage string) {
		if _, loaded := seenAssets.LoadOrStore(assetURL, true); loaded {
			return
		}
		assetWG.Add(1)
		go func() {
			defer assetWG.Done()
			assetSem <- struct{}{}
			defer func() { <-assetSem }()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxAssetSize+1))
			truncated := int64(len(body)) > opts.MaxAssetSize
			if truncated {
				body = body[:opts.MaxAssetSize]
			}
			bodyStr := string(body)

			extra := func(base string) string {
				if truncated {
					return base + " (asset truncated at size cap — results from this file may be incomplete)"
				}
				return base
			}

			for _, em := range findEndpoints(bodyStr) {
				if _, loaded := seenFindings.LoadOrStore("endpoint:"+em.value, true); loaded {
					continue
				}
				emit(finding{
					value:      em.value,
					source:     assetURL,
					confidence: em.confidence,
					extra:      extra(fmt.Sprintf("endpoint (%s) — not confirmed reachable, verify manually", em.kind)),
					size:       int64(len(body)),
				})
			}
			for _, sm := range findSecrets(bodyStr) {
				if _, loaded := seenFindings.LoadOrStore("secret:"+sm.label+":"+sm.masked, true); loaded {
					continue
				}
				emit(finding{
					value:      sm.masked,
					source:     assetURL,
					confidence: sm.confidence,
					extra:      extra(fmt.Sprintf("possible %s — verify before treating as a live credential", sm.label)),
					size:       int64(len(body)),
				})
			}
			for _, ref := range extractSourceMapRefs(bodyStr) {
				mapURL, err := resolveURL(assetURL, ref)
				if err != nil {
					mapURL = ref
				}
				if _, loaded := seenFindings.LoadOrStore("sourcemap:"+mapURL, true); loaded {
					continue
				}
				emit(finding{
					value:      mapURL,
					source:     assetURL,
					confidence: 95,
					extra:      "source map reference — fetching it may leak original (unminified) source file names/structure",
					size:       int64(len(body)),
				})
			}
		}()
	}

	for len(queue) > 0 && pagesVisited < opts.MaxPages {
		select {
		case <-ctx.Done():
			assetWG.Wait()
			return ctx.Err()
		default:
		}

		p := queue[0]
		queue = queue[1:]

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue // transport-level failure for one page; keep crawling others
		}
		pagesVisited++
		finalURL := p.url
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxAssetSize+1))
		resp.Body.Close()
		htmlStr := string(body)

		scripts, stylesheets, inlineBodies := extractAssetURLs(htmlStr)
		for _, s := range scripts {
			if assetURL, err := resolveURL(finalURL, s); err == nil {
				fetchAsset(assetURL, p.url)
			}
		}
		for _, s := range stylesheets {
			if assetURL, err := resolveURL(finalURL, s); err == nil {
				fetchAsset(assetURL, p.url)
			}
		}

		// Extract directly from the page HTML and inline scripts too.
		for _, em := range findEndpoints(htmlStr) {
			if _, loaded := seenFindings.LoadOrStore("endpoint:"+em.value, true); !loaded {
				emit(finding{value: em.value, source: p.url, confidence: em.confidence,
					extra: fmt.Sprintf("endpoint (%s) — not confirmed reachable, verify manually", em.kind), size: int64(len(body))})
			}
		}
		for _, inline := range inlineBodies {
			for _, em := range findEndpoints(inline) {
				if _, loaded := seenFindings.LoadOrStore("endpoint:"+em.value, true); !loaded {
					emit(finding{value: em.value, source: p.url + " (inline script)", confidence: em.confidence,
						extra: fmt.Sprintf("endpoint (%s) — not confirmed reachable, verify manually", em.kind), size: int64(len(inline))})
				}
			}
			for _, sm := range findSecrets(inline) {
				if _, loaded := seenFindings.LoadOrStore("secret:"+sm.label+":"+sm.masked, true); !loaded {
					emit(finding{value: sm.masked, source: p.url + " (inline script)", confidence: sm.confidence,
						extra: fmt.Sprintf("possible %s — verify before treating as a live credential", sm.label), size: int64(len(inline))})
				}
			}
		}

		if p.depth >= opts.Depth {
			continue
		}
		for _, href := range extractPageLinks(htmlStr) {
			linkURL, err := resolveURL(finalURL, href)
			if err != nil {
				continue
			}
			linkURL = stripFragment(linkURL)
			if opts.SameOrigin && !sameOrigin(linkURL, seed) {
				continue
			}
			if _, loaded := seenPages.LoadOrStore(linkURL, true); loaded {
				continue
			}
			queue = append(queue, page{url: linkURL, depth: p.depth + 1})
		}
	}

	assetWG.Wait()
	if strings.TrimSpace(opts.URL) == "" {
		return fmt.Errorf("crawl: empty target URL")
	}
	return nil
}

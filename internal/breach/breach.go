// Package breach checks whether a domain or email has surfaced in known data
// breaches or public paste-sites — the clear-web "leak checking" people often
// mean when they ask about deep/dark-web exposure. It does not crawl Tor/.onion
// sites; paste-site scraping and breach-database APIs are clear-web, indexable
// sources that happen to host leaked data.
package breach

import (
	"context"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options configures a breach-check run.
type Options struct {
	Query string // domain or email to check

	HIBPAPIKey string // https://haveibeenpwned.com/API/Key (paid)

	DehashedEmail  string // DeHashed auth is an (account email, API key) pair
	DehashedAPIKey string

	SkipPaste bool // skip the free Pastebin scraper

	Timeout    time.Duration
	RatePerSec float64
	Writer     output.Writer
}

// Run checks opts.Query against every configured provider and streams
// findings to opts.Writer. A provider that needs an API key the user didn't
// supply is skipped with an explicit stderr-visible reason via the returned
// skip list — never silently reported as "clean."
func Run(ctx context.Context, opts Options) ([]string, error) {
	client := utils.NewClient(utils.ClientConfig{Timeout: opts.Timeout})
	rl := utils.NewRateLimiter(opts.RatePerSec)

	var skipped []string
	emit := func(source, value, extra string) {
		_ = opts.Writer.Write(output.Result{
			Type:      output.TypeBreach,
			Value:     value,
			Source:    source,
			Extra:     extra,
			Timestamp: time.Now(),
		})
	}

	if opts.HIBPAPIKey != "" {
		if err := checkHIBP(ctx, client, rl, opts.HIBPAPIKey, opts.Query, emit); err != nil {
			skipped = append(skipped, "hibp (error: "+err.Error()+")")
		}
	} else {
		skipped = append(skipped, "hibp (no --hibp-key provided)")
	}

	if opts.DehashedAPIKey != "" && opts.DehashedEmail != "" {
		if err := checkDehashed(ctx, client, rl, opts.DehashedEmail, opts.DehashedAPIKey, opts.Query, emit); err != nil {
			skipped = append(skipped, "dehashed (error: "+err.Error()+")")
		}
	} else {
		skipped = append(skipped, "dehashed (no --dehashed-email/--dehashed-key provided)")
	}

	if !opts.SkipPaste {
		if err := checkPasteSites(ctx, client, rl, opts.Query, emit); err != nil {
			skipped = append(skipped, "paste-sites (error: "+err.Error()+")")
		}
	} else {
		skipped = append(skipped, "paste-sites (--skip-paste set)")
	}

	return skipped, nil
}

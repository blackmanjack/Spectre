package utils

import (
	"crypto/tls"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// DefaultUserAgents is the rotation pool of real browser UAs.
var DefaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Googlebot/2.1 (+http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"curl/7.88.1",
	"python-requests/2.31.0",
	"Go-http-client/1.1",
}

// ClientConfig holds all tunables for the shared HTTP client.
type ClientConfig struct {
	Timeout       time.Duration
	SkipTLSVerify bool
	FollowRedirs  bool
	MaxRedirects  int
	UserAgents    []string
	ExtraHeaders  http.Header
	Cookies       string
}

// NewClient returns a configured *http.Client safe for concurrent use.
// UA rotation is applied per-request via uaRoundTripper.
func NewClient(cfg ClientConfig) *http.Client {
	if cfg.UserAgents == nil {
		cfg.UserAgents = DefaultUserAgents
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 10
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec — user opt-in for pentest
		},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		ForceAttemptHTTP2:     false, // disable H2 to avoid stream multiplex interfering with rate limits
	}

	ua := &uaRoundTripper{
		base:         transport,
		pool:         cfg.UserAgents,
		extraHeaders: cfg.ExtraHeaders,
		cookies:      cfg.Cookies,
	}

	maxRedir := cfg.MaxRedirects
	followRedir := cfg.FollowRedirs

	return &http.Client{
		Transport: ua,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !followRedir {
				return http.ErrUseLastResponse
			}
			if len(via) >= maxRedir {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// uaRoundTripper rotates User-Agent and injects extra headers per request.
type uaRoundTripper struct {
	base         http.RoundTripper
	pool         []string
	extraHeaders http.Header
	cookies      string
	mu           sync.Mutex
	idx          int
}

func (u *uaRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("User-Agent", u.nextUA())
	for k, vals := range u.extraHeaders {
		for _, v := range vals {
			clone.Header.Set(k, v)
		}
	}
	if u.cookies != "" && clone.Header.Get("Cookie") == "" {
		clone.Header.Set("Cookie", u.cookies)
	}
	return u.base.RoundTrip(clone)
}

func (u *uaRoundTripper) nextUA() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	// Mix sequential + random for good distribution
	ua := u.pool[u.idx%len(u.pool)]
	u.idx++
	if u.idx%7 == 0 { // occasionally pick random
		ua = u.pool[rand.Intn(len(u.pool))]
	}
	return ua
}

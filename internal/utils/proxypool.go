package utils

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyPool rotates outbound connections through a list of HTTP/SOCKS5 proxies.
// Per-proxy health tracking: failed proxies are cooled down before reuse.
type ProxyPool struct {
	proxies  []proxyEntry
	mu       sync.Mutex
	idx      int
	disabled bool
}

type proxyEntry struct {
	url      string
	failures int64
	lastFail int64 // unix timestamp
}

const proxyCooldownSec = 30

// NewProxyPool creates a pool from a list of proxy URLs.
// Returns a pool with disabled=true if the list is empty.
func NewProxyPool(proxyURLs []string) *ProxyPool {
	if len(proxyURLs) == 0 {
		return &ProxyPool{disabled: true}
	}
	entries := make([]proxyEntry, 0, len(proxyURLs))
	for _, u := range proxyURLs {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}
		entries = append(entries, proxyEntry{url: u})
	}
	return &ProxyPool{proxies: entries}
}

// LoadProxyFile reads proxy URLs from a file (one per line).
func LoadProxyFile(path string) (*ProxyPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return NewProxyPool(urls), scanner.Err()
}

// IsDisabled reports whether no proxies are configured.
func (p *ProxyPool) IsDisabled() bool {
	return p == nil || p.disabled || len(p.proxies) == 0
}

// NewHTTPClient returns an *http.Client that routes through the next healthy proxy.
// If pool is disabled, returns a direct client (no proxy).
func (p *ProxyPool) NewHTTPClient(cfg ClientConfig) *http.Client {
	client := NewClient(cfg)
	if p.IsDisabled() {
		return client
	}
	idx := p.next()
	if idx < 0 {
		return client // all proxies cooling down
	}
	proxyURL, err := url.Parse(p.proxies[idx].url)
	if err != nil {
		return client
	}
	entry := &p.proxies[idx]
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: cfg.Timeout}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				atomic.AddInt64(&entry.failures, 1)
				atomic.StoreInt64(&entry.lastFail, time.Now().Unix())
			}
			return conn, err
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}
	client.Transport = &uaRoundTripper{
		base:         transport,
		pool:         DefaultUserAgents,
		extraHeaders: cfg.ExtraHeaders,
		cookies:      cfg.Cookies,
	}
	return client
}

// MarkFailed marks the proxy at idx as failed.
func (p *ProxyPool) MarkFailed(idx int) {
	if idx >= 0 && idx < len(p.proxies) {
		atomic.AddInt64(&p.proxies[idx].failures, 1)
		atomic.StoreInt64(&p.proxies[idx].lastFail, time.Now().Unix())
	}
}

func (p *ProxyPool) next() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().Unix()
	for i := 0; i < len(p.proxies); i++ {
		idx := p.idx % len(p.proxies)
		p.idx++
		entry := &p.proxies[idx]
		fails := atomic.LoadInt64(&entry.failures)
		lastFail := atomic.LoadInt64(&entry.lastFail)
		if fails == 0 || (now-lastFail) >= proxyCooldownSec {
			if fails > 0 {
				atomic.StoreInt64(&entry.failures, 0) // reset after cooldown
			}
			return idx
		}
	}
	return -1
}

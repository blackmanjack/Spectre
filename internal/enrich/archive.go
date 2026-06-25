package enrich

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// WaybackURLs extracts subdomains and URLs from Wayback Machine CDX API.
// Returns a channel of subdomain strings that match the domain.
func WaybackURLs(ctx context.Context, domain string, client *http.Client) <-chan string {
	out := make(chan string, 128)
	go func() {
		defer close(out)
		// CDX API: match_type=domain returns all URLs under the domain
		apiURL := fmt.Sprintf(
			"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=50000",
			url.QueryEscape(domain),
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		suffix := "." + domain
		seen := make(map[string]bool)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// Extract hostname from URL
			u, err := url.Parse(line)
			if err != nil {
				continue
			}
			host := strings.ToLower(u.Hostname())
			if host == "" {
				continue
			}
			// Only emit if it's a subdomain of our target
			if (strings.HasSuffix(host, suffix) || host == domain) && !seen[host] {
				seen[host] = true
				select {
				case out <- host:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// CommonCrawlURLs extracts subdomains from CommonCrawl index (latest index).
func CommonCrawlURLs(ctx context.Context, domain string, client *http.Client) <-chan string {
	out := make(chan string, 128)
	go func() {
		defer close(out)

		// Get latest index name
		indexURL := "https://index.commoncrawl.org/collinfo.json"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		var indexes []struct {
			ID  string `json:"id"`
			API string `json:"cdx-api"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&indexes); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if len(indexes) == 0 {
			return
		}

		// Use the most recent index
		apiBase := indexes[0].API
		searchURL := fmt.Sprintf("%s?url=*.%s&output=text&fl=url&limit=50000", apiBase, url.QueryEscape(domain))
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
		if err != nil {
			return
		}
		resp2, err := client.Do(req2)
		if err != nil {
			return
		}
		defer resp2.Body.Close()

		suffix := "." + domain
		seen := make(map[string]bool)
		scanner := bufio.NewScanner(resp2.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			u, err := url.Parse(line)
			if err != nil {
				continue
			}
			host := strings.ToLower(u.Hostname())
			if (strings.HasSuffix(host, suffix) || host == domain) && !seen[host] {
				seen[host] = true
				select {
				case out <- host:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

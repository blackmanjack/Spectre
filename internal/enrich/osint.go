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

// GitHubSearch searches GitHub code for subdomains of the given domain.
// Requires a GitHub token in the Authorization header for higher rate limits.
// Without a token, this uses the unauthenticated API (60 req/hour).
func GitHubSearch(ctx context.Context, domain string, client *http.Client, token string) <-chan string {
	out := make(chan string, 64)
	go func() {
		defer close(out)

		query := fmt.Sprintf("%s+extension:txt+extension:conf+extension:yaml+extension:json", domain)
		apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100", url.QueryEscape(query))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		if token != "" {
			req.Header.Set("Authorization", "token "+token)
		}

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 403 {
			fmt.Printf("[warn] GitHub search rate-limited (provide --github-token for higher limits)\n")
			return
		}
		if resp.StatusCode != 200 {
			return
		}

		var result struct {
			Items []struct {
				HTMLURL string `json:"html_url"`
			} `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return
		}

		suffix := "." + domain
		seen := make(map[string]bool)
		for _, item := range result.Items {
			// Fetch raw file content and scan for domain mentions
			rawURL := strings.Replace(item.HTMLURL, "github.com", "raw.githubusercontent.com", 1)
			rawURL = strings.Replace(rawURL, "/blob/", "/", 1)

			rawReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
			if err != nil {
				continue
			}
			rawResp, err := client.Do(rawReq)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(rawResp.Body)
			for scanner.Scan() {
				line := scanner.Text()
				// Simple extraction: find tokens ending in .domain
				fields := strings.Fields(line)
				for _, f := range fields {
					f = strings.Trim(f, `"',;:()[]{}`)
					f = strings.ToLower(f)
					if strings.HasSuffix(f, suffix) && !strings.Contains(f, " ") {
						if !seen[f] {
							seen[f] = true
							select {
							case out <- f:
							case <-ctx.Done():
								rawResp.Body.Close()
								return
							}
						}
					}
				}
			}
			rawResp.Body.Close()
		}
	}()
	return out
}

// SearchEngineDork queries a search engine for subdomains via site: operator.
// Uses the Bing search API (free tier, no key needed for basic queries).
func SearchEngineDork(ctx context.Context, domain string, client *http.Client) <-chan string {
	out := make(chan string, 64)
	go func() {
		defer close(out)
		// Use Bing Web Search (HTML scrape of site: dork — no API key required)
		query := url.QueryEscape("site:" + domain + " -www")
		searchURL := fmt.Sprintf("https://www.bing.com/search?q=%s&count=50", query)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
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
			line := scanner.Text()
			// Extract href/cite values containing domain
			for _, chunk := range strings.Split(line, `"`) {
				chunk = strings.ToLower(strings.TrimSpace(chunk))
				if strings.HasSuffix(chunk, suffix) || (strings.Contains(chunk, suffix+"/")) {
					host := chunk
					if idx := strings.Index(host, "/"); idx > 0 {
						host = host[:idx]
					}
					host = strings.TrimPrefix(host, "https://")
					host = strings.TrimPrefix(host, "http://")
					if strings.HasSuffix(host, suffix) && !seen[host] {
						seen[host] = true
						select {
						case out <- host:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()
	return out
}

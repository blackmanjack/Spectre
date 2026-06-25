package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// RapidDNS queries https://rapiddns.io/subdomain/{domain}?full=1
// Conservative HTML scraping: only extract strings ending in the domain suffix.
type RapidDNS struct{}

func (r *RapidDNS) Name() string { return "rapiddns" }

func (r *RapidDNS) Query(ctx context.Context, domain string, client *http.Client) (<-chan string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("rapiddns: HTTP %d", resp.StatusCode)
	}

	ch := make(chan string, 64)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		suffix := "." + domain
		scanner := bufio.NewScanner(resp.Body)
		found := 0
		for scanner.Scan() {
			line := scanner.Text()
			// Look for <td> cells containing domain names
			if !strings.Contains(line, "<td>") {
				continue
			}
			// Extract text between <td> and </td>
			start := strings.Index(line, "<td>")
			end := strings.Index(line, "</td>")
			if start < 0 || end < 0 || end <= start {
				continue
			}
			val := line[start+4 : end]
			val = strings.ToLower(strings.TrimSpace(val))
			// Conservative: only extract if it ends with the domain
			if strings.HasSuffix(val, suffix) || val == domain {
				val = strings.TrimPrefix(val, "*.")
				if val != "" {
					found++
					select {
					case ch <- val:
					case <-ctx.Done():
						return
					}
				}
			}
		}
		if found == 0 {
			// Warn in case HTML structure changed
			fmt.Printf("[warn] rapiddns: 0 results for %s (HTML structure may have changed)\n", domain)
		}
	}()
	return ch, nil
}

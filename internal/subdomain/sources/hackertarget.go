package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// HackerTarget queries https://api.hackertarget.com/hostsearch/?q={domain}
// Response is plain text: "subdomain,ip\n" per line.
type HackerTarget struct{}

func (h *HackerTarget) Name() string { return "hackertarget" }

func (h *HackerTarget) Query(ctx context.Context, domain string, client *http.Client) (<-chan string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("hackertarget: HTTP %d", resp.StatusCode)
	}

	ch := make(chan string, 64)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			// Detect API limit exceeded
			if strings.Contains(line, "API count exceeded") || strings.Contains(line, "error") {
				fmt.Printf("[warn] hackertarget: %s\n", line)
				return
			}
			// Format: subdomain,ip
			parts := strings.SplitN(line, ",", 2)
			if len(parts) < 1 {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name != "" && strings.Contains(name, ".") {
				select {
				case ch <- name:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AlienVault queries OTX passive DNS with pagination.
type AlienVault struct{}

func (a *AlienVault) Name() string { return "alienvault" }

func (a *AlienVault) Query(ctx context.Context, domain string, client *http.Client) (<-chan string, error) {
	ch := make(chan string, 64)
	go func() {
		defer close(ch)
		page := 1
		for {
			url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns?page=%d", domain, page)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return
			}

			var result struct {
				PassiveDNS []struct {
					Hostname string `json:"hostname"`
				} `json:"passive_dns"`
				HasNext bool   `json:"has_next"`
				Next    string `json:"next"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			for _, entry := range result.PassiveDNS {
				name := strings.ToLower(strings.TrimSpace(entry.Hostname))
				name = strings.TrimPrefix(name, "*.")
				if name != "" && strings.Contains(name, ".") {
					select {
					case ch <- name:
					case <-ctx.Done():
						return
					}
				}
			}

			if !result.HasNext {
				break
			}
			page++
			// Safety: cap pages to avoid infinite loop on malformed response
			if page > 20 {
				break
			}
		}
	}()
	return ch, nil
}

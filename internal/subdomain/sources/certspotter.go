package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// CertSpotter queries https://api.certspotter.com/v1/issuances for CT logs.
type CertSpotter struct{}

func (c *CertSpotter) Name() string { return "certspotter" }

func (c *CertSpotter) Query(ctx context.Context, domain string, client *http.Client) (<-chan string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
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
		return nil, fmt.Errorf("certspotter: HTTP %d", resp.StatusCode)
	}

	ch := make(chan string, 64)
	go func() {
		defer close(ch)
		defer resp.Body.Close()

		var results []struct {
			DNSNames []string `json:"dns_names"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
			return
		}
		suffix := "." + domain
		for _, r := range results {
			for _, name := range r.DNSNames {
				name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "*."))
				if name != "" && (strings.HasSuffix(name, suffix) || name == domain) {
					select {
					case ch <- name:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return ch, nil
}

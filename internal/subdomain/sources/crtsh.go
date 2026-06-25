package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// CrtSH queries https://crt.sh/?q=%25.{domain}&output=json
// Stream-decodes with json.Decoder to avoid buffering huge responses.
type CrtSH struct{}

func (c *CrtSH) Name() string { return "crtsh" }

func (c *CrtSH) Query(ctx context.Context, domain string, client *http.Client) (<-chan string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("crtsh: HTTP %d", resp.StatusCode)
	}

	ch := make(chan string, 64)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		dec := json.NewDecoder(resp.Body)

		// Read opening bracket
		if _, err := dec.Token(); err != nil {
			return
		}
		for dec.More() {
			var entry struct {
				NameValue string `json:"name_value"`
			}
			if err := dec.Decode(&entry); err != nil {
				continue
			}
			for _, name := range strings.Split(entry.NameValue, "\n") {
				name = strings.TrimSpace(name)
				name = strings.TrimPrefix(name, "*.")
				name = strings.ToLower(name)
				if name != "" && strings.Contains(name, ".") {
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

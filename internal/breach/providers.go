package breach

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spectre-tool/spectre/internal/utils"
)

type emitFunc func(source, value, extra string)

// checkHIBP queries HaveIBeenPwned's breach API. Requires a paid API key
// (https://haveibeenpwned.com/API/Key) — the free tier was retired in 2024.
// Only accepts email-shaped queries; HIBP has no domain-breach endpoint on
// the consumer API tier.
func checkHIBP(ctx context.Context, client *http.Client, rl *utils.RateLimiter, apiKey, query string, emit emitFunc) error {
	if !strings.Contains(query, "@") {
		return fmt.Errorf("HIBP only supports email queries, got %q", query)
	}
	if err := rl.Wait(ctx); err != nil {
		return err
	}

	url := "https://haveibeenpwned.com/api/v3/breachedaccount/" + query + "?truncateResponse=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("hibp-api-key", apiKey)
	req.Header.Set("User-Agent", "spectre-recon")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil // no breaches found — not an error
	case http.StatusOK:
	default:
		return fmt.Errorf("HIBP returned HTTP %d", resp.StatusCode)
	}

	var breaches []struct {
		Name        string `json:"Name"`
		Domain      string `json:"Domain"`
		BreachDate  string `json:"BreachDate"`
		PwnCount    int    `json:"PwnCount"`
		DataClasses []string `json:"DataClasses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return err
	}
	for _, b := range breaches {
		emit("hibp", b.Name, fmt.Sprintf("date=%s accounts=%d classes=%s",
			b.BreachDate, b.PwnCount, strings.Join(b.DataClasses, ",")))
	}
	return nil
}

// checkDehashed queries DeHashed's search API. Auth is an (account email, API
// key) basic-auth pair, not a bearer token — this is the generic
// bring-your-own-key shape: the user supplies their own DeHashed account
// credentials, this code is just the HTTP plumbing.
func checkDehashed(ctx context.Context, client *http.Client, rl *utils.RateLimiter, account, apiKey, query string, emit emitFunc) error {
	if err := rl.Wait(ctx); err != nil {
		return err
	}

	field := "domain"
	if strings.Contains(query, "@") {
		field = "email"
	}
	url := fmt.Sprintf("https://api.dehashed.com/search?query=%s:%s", field, query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(account, apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DeHashed returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Total   int `json:"total"`
		Entries []struct {
			DatabaseName string `json:"database_name"`
			Email        string `json:"email"`
			Username     string `json:"username"`
			PasswordHash string `json:"hashed_password"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	for _, e := range result.Entries {
		detail := "user=" + e.Username
		if e.PasswordHash != "" {
			detail += " (hash present)"
		}
		emit("dehashed", e.DatabaseName, detail)
	}
	return nil
}

// checkPasteSites scrapes Pastebin's public "scrape" endpoint for recent
// pastes mentioning query. This only sees the last ~30 minutes of public
// pastes (Pastebin's free scraping API offers no historical search), so it
// is a best-effort tripwire, not a comprehensive paste-site search.
// Pastebin also IP-whitelists this endpoint (https://pastebin.com/doc_scraping_api)
// — unwhitelisted IPs get HTTP 403, which surfaces as a normal skip reason
// rather than a crash.
func checkPasteSites(ctx context.Context, client *http.Client, rl *utils.RateLimiter, query string, emit emitFunc) error {
	if err := rl.Wait(ctx); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://scrape.pastebin.com/api_scraping.php?limit=100", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pastebin scrape endpoint returned HTTP %d", resp.StatusCode)
	}

	var pastes []struct {
		Key    string `json:"key"`
		Title  string `json:"title"`
		Date   string `json:"date"`
		Size   string `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pastes); err != nil {
		return err
	}

	queryLower := strings.ToLower(query)
	for _, p := range pastes {
		if err := rl.Wait(ctx); err != nil {
			return err
		}
		rawReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://scrape.pastebin.com/api_scrape_item.php?i="+p.Key, nil)
		if err != nil {
			continue
		}
		rawResp, err := client.Do(rawReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(rawResp.Body, 256*1024))
		rawResp.Body.Close()

		if strings.Contains(strings.ToLower(string(body)), queryLower) {
			emit("pastebin", p.Title, "paste="+p.Key+" date="+p.Date+" size="+p.Size)
		}
	}
	return nil
}

package dirfuzz

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"unicode"
)

// buildPaths expands a word + extensions into all paths to probe.
// E.g. word="admin", exts=["php","html"] -> ["/admin", "/admin.php", "/admin.html"]
func buildPaths(word string, exts []string) []string {
	word = strings.TrimPrefix(word, "/")
	paths := []string{"/" + word}
	for _, ext := range exts {
		ext = strings.TrimPrefix(ext, ".")
		paths = append(paths, "/"+word+"."+ext)
	}
	return paths
}

// probe sends one HTTP request and returns a ProbeResult.
// Reads only the first 4KB of body for filtering; discards the rest.
func probe(ctx context.Context, client *http.Client, method, baseURL, path string, extraHeaders http.Header) (ProbeResult, error) {
	target := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return ProbeResult{}, err
	}
	for k, vals := range extraHeaders {
		for _, v := range vals {
			req.Header.Set(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{}, err
	}
	defer resp.Body.Close()

	// Read first 4KB for body analysis, discard rest
	buf := make([]byte, 4096)
	n, _ := io.ReadFull(resp.Body, buf)
	body := buf[:n]
	// Drain remaining to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	size := resp.ContentLength
	if size < 0 {
		size = int64(n) // fallback for chunked
	}

	words := countWords(body)
	lines := bytes.Count(body, []byte("\n")) + 1

	return ProbeResult{
		Path:   path,
		Status: resp.StatusCode,
		Size:   size,
		Words:  words,
		Lines:  lines,
		Body:   body,
	}, nil
}

// calibrateSoft404 probes a random path to fingerprint the soft-404 response.
// Returns the body fingerprint and size if the random path returns non-404.
func calibrateSoft404(ctx context.Context, client *http.Client, baseURL string) ([]byte, int64, error) {
	randomPath := "/spectre-probe-" + mustRandomHex(8)
	r, err := probe(ctx, client, http.MethodGet, baseURL, randomPath, nil)
	if err != nil || r.Status == 404 {
		return nil, 0, err
	}
	// Non-404 response to random path — soft-404 detected
	return r.Body, r.Size, nil
}

func countWords(b []byte) int {
	inWord := false
	count := 0
	for _, c := range b {
		if unicode.IsSpace(rune(c)) {
			inWord = false
		} else if !inWord {
			inWord = true
			count++
		}
	}
	return count
}

func mustRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "deadbeef"
	}
	return hex.EncodeToString(b)
}

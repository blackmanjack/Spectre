package analyze

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
)

// isURL reports whether entry looks like a URL (has a scheme separator)
// rather than a local filesystem path.
func isURL(entry string) bool {
	return strings.Contains(entry, "://")
}

// loadSource reads body from a local file path or fetches it via HTTP,
// capped at maxSize bytes either way.
func loadSource(ctx context.Context, entry string, client *http.Client, maxSize int64) (body string, truncated bool, err error) {
	if isURL(entry) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, entry, nil)
		if err != nil {
			return "", false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", false, err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
		truncated = int64(len(data)) > maxSize
		if truncated {
			data = data[:maxSize]
		}
		return string(data), truncated, nil
	}

	f, err := os.Open(entry)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, maxSize+1))
	truncated = int64(len(data)) > maxSize
	if truncated {
		data = data[:maxSize]
	}
	return string(data), truncated, nil
}

package wordlists

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// LocalDir returns the directory where pulled wordlists are stored.
func LocalDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".spectre", "wordlists")
	return dir, os.MkdirAll(dir, 0700)
}

// LocalPath returns the local filesystem path for a named list.
func LocalPath(name string) (string, error) {
	dir, err := LocalDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".txt"), nil
}

// IsPulled reports whether the named list has been downloaded locally.
func IsPulled(name string) bool {
	p, err := LocalPath(name)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Pull downloads a wordlist from its upstream URL to the local store.
// It verifies the sha256 if one is provided in the catalog entry.
// Prints license info to stdout for user transparency.
func Pull(e Entry, progressFn func(downloaded, total int64)) error {
	localPath, err := LocalPath(e.Name)
	if err != nil {
		return err
	}

	fmt.Printf("[spectre] Pulling %q from %s\n", e.Name, e.URL)
	fmt.Printf("[spectre] License: %s | Please review upstream license before use.\n", e.License)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(e.URL) //nolint:noctx — timeout via client
	if err != nil {
		return fmt.Errorf("fetching %s: %w", e.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, e.URL)
	}

	tmpPath := localPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	h := sha256.New()
	var downloaded int64
	total := resp.ContentLength

	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				os.Remove(tmpPath)
				return werr
			}
			h.Write(buf[:n])
			downloaded += int64(n)
			if progressFn != nil {
				progressFn(downloaded, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(tmpPath)
			return rerr
		}
	}
	f.Close()

	// Verify sha256 if catalog provides one
	if e.SHA256 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != e.SHA256 {
			os.Remove(tmpPath)
			return fmt.Errorf("sha256 mismatch for %s: expected %s, got %s", e.Name, e.SHA256, got)
		}
	}

	if err := os.Rename(tmpPath, localPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	fmt.Printf("[spectre] Saved %q -> %s (%d bytes)\n", e.Name, localPath, downloaded)
	return nil
}

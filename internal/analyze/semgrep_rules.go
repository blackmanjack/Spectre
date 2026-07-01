package analyze

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed rules/*.yml
var embeddedRules embed.FS

// resolveRuleset returns a filesystem path suitable for semgrep's --config
// flag. If override is non-empty, it's passed through unchanged (a registry
// name like "p/javascript" or a local path the caller supplied). Otherwise
// SPECTRE's embedded offline ruleset is written to a temp directory, since
// semgrep requires a real filesystem path, not an in-memory FS. The returned
// cleanup func removes that temp directory; it is a no-op when override was
// used.
func resolveRuleset(override string) (path string, cleanup func(), err error) {
	if override != "" {
		return override, func() {}, nil
	}

	dir, err := os.MkdirTemp("", "spectre-semgrep-rules-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }

	entries, err := embeddedRules.ReadDir("rules")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	for _, e := range entries {
		data, err := embeddedRules.ReadFile("rules/" + e.Name())
		if err != nil {
			cleanup()
			return "", nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o600); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return dir, cleanup, nil
}

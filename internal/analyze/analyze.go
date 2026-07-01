// Package analyze runs pattern/sink-source based static vulnerability
// detection over JS, HTML, and ASP/ASPX source — DOM XSS sinks, auth-bypass
// indicators, and SQL-injection-prone patterns. This is regex + proximity
// heuristics, not AST-level taint-flow analysis: every finding is a pattern
// match that requires manual verification, never an assertion that a
// vulnerability is confirmed or exploitable.
package analyze

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options configures an analyze run.
type Options struct {
	Target         string // file path, directory path, or .txt list path
	Timeout        time.Duration
	SkipTLS        bool
	MaxFileSize    int64 // bytes; 0 defaults to 10MB
	Concurrency    int
	Categories     []string // subset of {dom-xss, auth-bypass, sqli}; empty = all
	MinConfidence  int
	EmbeddedFS     fs.FS
	Engine         string // "regex" (default), "semgrep", or "both"
	SemgrepRuleset string // "" = use SPECTRE's embedded offline ruleset
	SemgrepTimeout time.Duration
	Writer         output.Writer
}

var allCategories = map[string]func(string) []finding{
	"dom-xss":        scanDOMXSS,
	"auth-bypass":    scanAuthBypass,
	"sqli":           scanSQLi,
	"xxe-upload":     scanXXEUpload,
	"mass-assignment": scanMassAssignment,
	"ai-sdk-exposure": scanAISDKExposure,
}

// Run auto-detects the target's input mode (single file, directory, or a
// .txt list of paths/URLs) and runs the enabled detection categories over
// every resolved source body.
func Run(ctx context.Context, opts Options) error {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 10 * 1024 * 1024
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	scanners := resolveCategories(opts.Categories)

	client := utils.NewClient(utils.ClientConfig{
		Timeout:       opts.Timeout,
		SkipTLSVerify: opts.SkipTLS,
		FollowRedirs:  true,
		MaxRedirects:  5,
	})

	emit := func(f finding, source string, fileSize int64, fileLines int) {
		if f.confidence < opts.MinConfidence {
			return
		}
		extra := f.extra
		if guidance := howToTest(f.category); guidance != "" {
			extra += "\n\n" + guidance
		}
		_ = opts.Writer.Write(output.Result{
			Type:       output.TypeAnalyze,
			Value:      f.category,
			Source:     source,
			Confidence: f.confidence,
			Extra:      extra,
			Size:       fileSize,
			Lines:      fileLines,
			Timestamp:  time.Now(),
		})
	}

	scanOne := func(body, source string, truncated bool) {
		fileLines := strings.Count(body, "\n") + 1
		for _, scan := range scanners {
			for _, f := range scan(body) {
				extra := f.extra
				if truncated {
					extra += " (file truncated at size cap — later content was not scanned)"
				}
				emit(finding{category: f.category, value: f.value, confidence: f.confidence, position: f.position, extra: extra},
					source, int64(len(body)), fileLines)
			}
		}
	}

	engine := opts.Engine
	if engine == "" {
		engine = "regex"
	}

	switch engine {
	case "regex":
		return runRegexEngine(ctx, opts, client, scanOne)
	case "semgrep":
		return runSemgrepEngine(ctx, opts, emit)
	case "both":
		if err := runRegexEngine(ctx, opts, client, scanOne); err != nil {
			return err
		}
		return runSemgrepEngine(ctx, opts, emit)
	default:
		return fmt.Errorf("unknown engine %q: must be regex, semgrep, or both", engine)
	}
}

// runRegexEngine dispatches opts.Target to directory/file/list mode and
// runs the regex scanners over every resolved source body, unchanged from
// before the semgrep engine was added.
func runRegexEngine(ctx context.Context, opts Options, client *http.Client, scanOne func(body, source string, truncated bool)) error {
	info, statErr := os.Stat(opts.Target)

	switch {
	case statErr == nil && info.IsDir():
		files, err := walkDirectory(opts.Target)
		if err != nil {
			return err
		}
		return scanConcurrent(ctx, files, opts.Concurrency, func(path string) {
			body, truncated, err := loadSource(ctx, path, client, opts.MaxFileSize)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[warn] analyze: %s: %v\n", path, err)
				return
			}
			scanOne(body, path, truncated)
		})

	case statErr == nil && !info.IsDir() && !strings.EqualFold(filepath.Ext(opts.Target), ".txt"):
		body, truncated, err := loadSource(ctx, opts.Target, client, opts.MaxFileSize)
		if err != nil {
			return err
		}
		scanOne(body, opts.Target, truncated)
		return nil

	default:
		// .txt list mode (file or URL list), or target that doesn't exist
		// locally and isn't a directory — try loading it as a list file.
		loader := utils.NewWordlistLoader(opts.EmbeddedFS)
		ch, err := loader.Load(opts.Target, "")
		if err != nil {
			return fmt.Errorf("analyze: target %q is not a file, directory, or readable list: %w", opts.Target, err)
		}
		var entries []string
		for line := range ch {
			entries = append(entries, line)
		}
		return scanConcurrent(ctx, entries, opts.Concurrency, func(entry string) {
			body, truncated, err := loadSource(ctx, entry, client, opts.MaxFileSize)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[warn] analyze: %s: %v\n", entry, err)
				return
			}
			scanOne(body, entry, truncated)
		})
	}
}

// runSemgrepEngine resolves the ruleset (embedded default, or the
// --semgrep-ruleset override), runs semgrep against opts.Target directly
// (semgrep needs a real file/directory path, not a pre-loaded body string,
// since it does its own parsing/taint analysis), and emits each result.
func runSemgrepEngine(ctx context.Context, opts Options, emit func(f finding, source string, fileSize int64, fileLines int)) error {
	binPath, ok := SemgrepAvailable()
	if !ok {
		return fmt.Errorf("semgrep binary not found on PATH (this should have been caught before Run was called)")
	}

	ruleset, cleanup, err := resolveRuleset(opts.SemgrepRuleset)
	if err != nil {
		return fmt.Errorf("failed to prepare semgrep ruleset: %w", err)
	}
	defer cleanup()

	timeout := opts.SemgrepTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	// semgrep requires a real file/directory path — .txt list mode is not
	// supported because semgrep does its own filesystem traversal and cannot
	// accept pre-fetched URL bodies. Detect early and surface a clear error
	// rather than letting semgrep try to parse a URL-list as source code.
	if strings.EqualFold(filepath.Ext(opts.Target), ".txt") {
		return fmt.Errorf("semgrep engine does not support .txt URL/path lists (target: %q); use --engine regex for list mode", opts.Target)
	}

	raw, err := runSemgrep(ctx, binPath, ruleset, opts.Target, timeout)
	if err != nil {
		return fmt.Errorf("semgrep run failed: %w", err)
	}

	findings, err := parseSemgrepJSON(raw)
	if err != nil {
		return fmt.Errorf("failed to parse semgrep output: %w", err)
	}
	for _, sf := range findings {
		emit(sf.f, sf.path, 0, 0)
	}
	return nil
}

func resolveCategories(names []string) []func(string) []finding {
	if len(names) == 0 {
		return []func(string) []finding{scanDOMXSS, scanAuthBypass, scanSQLi, scanXXEUpload, scanMassAssignment, scanAISDKExposure}
	}
	var out []func(string) []finding
	for _, n := range names {
		if fn, ok := allCategories[strings.TrimSpace(n)]; ok {
			out = append(out, fn)
		}
	}
	return out
}

func scanConcurrent(ctx context.Context, items []string, concurrency int, fn func(string)) error {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, item := range items {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		default:
		}
		wg.Add(1)
		go func(item string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(item)
		}(item)
	}
	wg.Wait()
	return nil
}

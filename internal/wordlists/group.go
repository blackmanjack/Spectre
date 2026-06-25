package wordlists

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
)

// Resolver resolves wordlist specifications to merged, deduplicated word channels.
// Specs can be:
//   - A named list:    "raft-medium-dirs"
//   - A tag group:     "directory:medium" or "subdomain:large"
//   - A file path:     "/path/to/custom.txt"
//   - A comma list:    "raft-medium-dirs,orwa-short"
type Resolver struct {
	catalog  *Catalog
	embedded fs.FS
}

// NewResolver creates a group resolver.
func NewResolver(catalog *Catalog, embedded fs.FS) *Resolver {
	return &Resolver{catalog: catalog, embedded: embedded}
}

// Resolve parses a spec, collects all matching list paths/sources,
// merges them and returns a deduplicated channel of words.
// Missing pulled lists cause a helpful error suggesting `spectre wordlists pull`.
func (r *Resolver) Resolve(spec string) (<-chan string, int, error) {
	sources, err := r.resolveSources(spec)
	if err != nil {
		return nil, 0, err
	}
	if len(sources) == 0 {
		return nil, 0, fmt.Errorf("no wordlists matched %q — try `spectre wordlists pull %s`", spec, spec)
	}

	out := make(chan string, 1024)
	go func() {
		defer close(out)
		seen := make(map[string]struct{}, 10000)
		var mu sync.Mutex
		var wg sync.WaitGroup

		// Fan-in: read all sources, dedup into out
		merge := make(chan string, 512)
		for _, src := range sources {
			wg.Add(1)
			go func(s wordSource) {
				defer wg.Done()
				ch, err := s.open()
				if err != nil {
					fmt.Printf("[warn] wordlist %s: %v\n", s.name, err)
					return
				}
				for word := range ch {
					merge <- word
				}
			}(src)
		}
		go func() {
			wg.Wait()
			close(merge)
		}()

		for word := range merge {
			mu.Lock()
			_, dup := seen[word]
			if !dup {
				seen[word] = struct{}{}
			}
			mu.Unlock()
			if !dup {
				out <- word
			}
		}
	}()
	return out, len(sources), nil
}

type wordSource struct {
	name string
	open func() (<-chan string, error)
}

func (r *Resolver) resolveSources(spec string) ([]wordSource, error) {
	var sources []wordSource
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		srcs, err := r.resolveOne(part)
		if err != nil {
			return nil, err
		}
		sources = append(sources, srcs...)
	}
	return sources, nil
}

func (r *Resolver) resolveOne(spec string) ([]wordSource, error) {
	// File path
	if strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, `.\`) {
		return []wordSource{{name: spec, open: func() (<-chan string, error) {
			return fileChannel(spec)
		}}}, nil
	}

	// Tag group: "category:size" e.g. "directory:medium", "subdomain:large"
	if strings.Contains(spec, ":") {
		if r.catalog == nil {
			return nil, fmt.Errorf("no wordlist catalog loaded — cannot resolve group %q", spec)
		}
		tags := strings.Split(spec, ":")
		entries := r.catalog.ByTags(tags...)
		var sources []wordSource
		for _, e := range entries {
			e := e
			if IsPulled(e.Name) {
				p, _ := LocalPath(e.Name)
				sources = append(sources, wordSource{name: e.Name, open: func() (<-chan string, error) {
					return fileChannel(p)
				}})
			}
		}
		if len(sources) == 0 {
			// Suggest pull
			fmt.Printf("[info] No pulled wordlists match %q. Run: spectre wordlists pull %s\n", spec, spec)
		}
		return sources, nil
	}

	// Named list
	if e := catalogByName(r.catalog, spec); e != nil {
		if IsPulled(e.Name) {
			p, _ := LocalPath(e.Name)
			return []wordSource{{name: e.Name, open: func() (<-chan string, error) {
				return fileChannel(p)
			}}}, nil
		}
		// Fall back to embedded if it happens to match
		if r.embedded != nil {
			if f, err := r.embedded.Open(spec + ".txt"); err == nil {
				f.Close()
				return []wordSource{{name: spec, open: func() (<-chan string, error) {
					return embeddedChannel(r.embedded, spec+".txt")
				}}}, nil
			}
		}
		return nil, fmt.Errorf("wordlist %q not pulled — run: spectre wordlists pull %s", spec, spec)
	}

	// Try embedded by default name
	if r.embedded != nil {
		name := spec
		if !strings.HasSuffix(name, ".txt") {
			name += ".txt"
		}
		if f, err := r.embedded.Open(name); err == nil {
			f.Close()
			return []wordSource{{name: spec, open: func() (<-chan string, error) {
				return embeddedChannel(r.embedded, name)
			}}}, nil
		}
	}

	return nil, fmt.Errorf("unknown wordlist %q — check `spectre wordlists list`", spec)
}

// catalogByName is a nil-safe wrapper around Catalog.ByName.
func catalogByName(c *Catalog, name string) *Entry {
	if c == nil {
		return nil
	}
	return c.ByName(name)
}

func fileChannel(path string) (<-chan string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ch := make(chan string, 512)
	go func() {
		defer close(ch)
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				ch <- line
			}
		}
	}()
	return ch, nil
}

func embeddedChannel(embedded fs.FS, name string) (<-chan string, error) {
	f, err := embedded.Open(name)
	if err != nil {
		return nil, err
	}
	ch := make(chan string, 512)
	go func() {
		defer close(ch)
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				ch <- line
			}
		}
	}()
	return ch, nil
}

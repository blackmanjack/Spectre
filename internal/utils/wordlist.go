package utils

import (
	"bufio"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"strings"
)

// WordlistLoader handles both embedded and file-based wordlists.
type WordlistLoader struct {
	embedded fs.FS
}

// NewWordlistLoader creates a loader with the given embedded FS.
func NewWordlistLoader(embedded fs.FS) *WordlistLoader {
	return &WordlistLoader{embedded: embedded}
}

// Load returns a channel of trimmed, non-empty, non-comment lines.
// If path is non-empty, reads from that file. Otherwise uses embeddedName from the embedded FS.
// Supports .gz files transparently.
// The channel is closed when all words have been sent or ctx is done.
func (l *WordlistLoader) Load(path, embeddedName string) (<-chan string, error) {
	var reader io.ReadCloser
	var err error

	if path != "" {
		reader, err = openFile(path)
	} else {
		reader, err = l.openEmbedded(embeddedName)
	}
	if err != nil {
		return nil, err
	}

	ch := make(chan string, 512)
	go func() {
		defer close(ch)
		defer reader.Close()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ch <- line
		}
	}()
	return ch, nil
}

// Count counts entries without keeping them in memory.
func (l *WordlistLoader) Count(path, embeddedName string) (int, error) {
	var reader io.ReadCloser
	var err error
	if path != "" {
		reader, err = openFile(path)
	} else {
		reader, err = l.openEmbedded(embeddedName)
	}
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	count := 0
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count, scanner.Err()
}

func (l *WordlistLoader) openEmbedded(name string) (io.ReadCloser, error) {
	f, err := l.embedded.Open(name)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(name, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &gzReadCloser{gz: gz, f: f}, nil
	}
	return f, nil
}

func openFile(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &gzReadCloser{gz: gz, f: f}, nil
	}
	return f, nil
}

type gzReadCloser struct {
	gz *gzip.Reader
	f  io.Closer
}

func (g *gzReadCloser) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g *gzReadCloser) Close() error {
	err := g.gz.Close()
	g.f.Close()
	return err
}

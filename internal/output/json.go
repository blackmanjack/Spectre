package output

import (
	"encoding/json"
	"io"
	"sync"
)

// JSONWriter streams NDJSON (one JSON object per line) to dest.
// Thread-safe: multiple goroutines may call Write concurrently.
type JSONWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONWriter creates an NDJSON streaming writer.
func NewJSONWriter(dest io.Writer) *JSONWriter {
	enc := json.NewEncoder(dest)
	enc.SetEscapeHTML(false)
	return &JSONWriter{enc: enc}
}

func (w *JSONWriter) Write(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(r)
}

func (w *JSONWriter) Flush() error { return nil }
func (w *JSONWriter) Close() error { return nil }

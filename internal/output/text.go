package output

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// TextWriter formats results as colored, human-readable lines.
type TextWriter struct {
	mu      sync.Mutex
	dest    io.Writer
	noColor bool
}

// NewTextWriter creates a colored terminal writer.
func NewTextWriter(dest io.Writer, noColor bool) *TextWriter {
	return &TextWriter{dest: dest, noColor: noColor}
}

func (w *TextWriter) Write(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	line := w.format(r)
	_, err := fmt.Fprintln(w.dest, line)
	return err
}

func (w *TextWriter) Flush() error { return nil }
func (w *TextWriter) Close() error { return nil }

func (w *TextWriter) format(r Result) string {
	if w.noColor {
		return w.formatPlain(r)
	}
	return w.formatColor(r)
}

func (w *TextWriter) formatPlain(r Result) string {
	switch r.Type {
	case TypeSubdomain:
		ips := ""
		if len(r.IPs) > 0 {
			ips = " [" + strings.Join(r.IPs, ", ") + "]"
		}
		return fmt.Sprintf("[%s] %s%s", r.Source, r.Value, ips)
	case TypeDirFuzz:
		return fmt.Sprintf("[%d] %-60s [size:%d words:%d lines:%d]", r.Status, r.Value, r.Size, r.Words, r.Lines)
	case TypePort:
		svc := r.Service
		if r.Version != "" {
			svc += "/" + r.Version
		}
		return fmt.Sprintf("%d/%s\t%s\t%s", r.Port, r.Protocol, r.State, svc)
	case TypeDNS:
		return fmt.Sprintf("[%s] %s", r.Source, r.Value)
	case TypeWebTech:
		extra := ""
		if r.Extra != "" {
			extra = " (" + r.Extra + ")"
		}
		return fmt.Sprintf("[webtech] %s%s", r.Value, extra)
	case TypeBreach:
		return fmt.Sprintf("[%s] %s — %s", r.Source, r.Value, r.Extra)
	case TypeStack:
		ver := ""
		if r.Version != "" {
			ver = " v" + r.Version
		}
		conf := ""
		if r.Confidence > 0 {
			conf = fmt.Sprintf(" (confidence:%d%%)", r.Confidence)
		}
		extra := ""
		if r.Extra != "" {
			extra = " — " + r.Extra
		}
		return fmt.Sprintf("[%s] %s%s%s%s", r.Source, r.Value, ver, conf, extra)
	case TypeCrawl, TypeAnalyze:
		conf := ""
		if r.Confidence > 0 {
			conf = fmt.Sprintf(" (confidence:%d%%)", r.Confidence)
		}
		extra := ""
		if r.Extra != "" {
			extra = " — " + r.Extra
		}
		return fmt.Sprintf("[%s] %s%s%s", r.Source, r.Value, conf, extra)
	default:
		return fmt.Sprintf("[%s] %s", r.Type, r.Value)
	}
}

func (w *TextWriter) formatColor(r Result) string {
	switch r.Type {
	case TypeSubdomain:
		ips := ""
		if len(r.IPs) > 0 {
			ips = colorDim + " [" + strings.Join(r.IPs, ", ") + "]" + colorReset
		}
		src := colorYellow + "[" + r.Source + "]" + colorReset
		val := colorGreen + colorBold + r.Value + colorReset
		return fmt.Sprintf("%s %s%s", src, val, ips)

	case TypeDirFuzz:
		statusColor := statusCodeColor(r.Status)
		code := statusColor + fmt.Sprintf("[%d]", r.Status) + colorReset
		path := colorCyan + r.Value + colorReset
		meta := colorDim + fmt.Sprintf("[size:%d words:%d lines:%d]", r.Size, r.Words, r.Lines) + colorReset
		return fmt.Sprintf("%s %-60s %s", code, path, meta)

	case TypePort:
		stateColor := colorRed
		if r.State == "open" {
			stateColor = colorGreen
		} else if r.State == "open|filtered" {
			stateColor = colorYellow
		}
		svc := r.Service
		if r.Version != "" {
			svc += colorDim + "/" + r.Version + colorReset
		}
		return fmt.Sprintf("%s%-6d/%s%s\t%s%s%s\t%s",
			colorBold, r.Port, r.Protocol, colorReset,
			stateColor, r.State, colorReset,
			svc)

	case TypeDNS:
		return fmt.Sprintf("%s[%s]%s %s", colorBlue, r.Source, colorReset, r.Value)

	case TypeWebTech:
		extra := ""
		if r.Extra != "" {
			extra = colorDim + " (" + r.Extra + ")" + colorReset
		}
		return fmt.Sprintf("%s[webtech]%s %s%s%s%s",
			colorCyan, colorReset,
			colorGreen, r.Value, colorReset, extra)

	case TypeBreach:
		src := colorRed + colorBold + "[" + r.Source + "]" + colorReset
		val := colorYellow + r.Value + colorReset
		return fmt.Sprintf("%s %s %s%s%s", src, val, colorDim, r.Extra, colorReset)

	case TypeStack:
		src := colorBlue + "[" + r.Source + "]" + colorReset
		val := colorGreen + colorBold + r.Value + colorReset
		ver := ""
		if r.Version != "" {
			ver = colorYellow + " v" + r.Version + colorReset
		}
		conf := ""
		if r.Confidence > 0 {
			conf = colorDim + fmt.Sprintf(" (confidence:%d%%)", r.Confidence) + colorReset
		}
		extra := ""
		if r.Extra != "" {
			extra = colorDim + " — " + r.Extra + colorReset
		}
		return fmt.Sprintf("%s %s%s%s%s", src, val, ver, conf, extra)

	case TypeCrawl, TypeAnalyze:
		src := colorBlue + "[" + r.Source + "]" + colorReset
		val := colorGreen + colorBold + r.Value + colorReset
		conf := ""
		if r.Confidence > 0 {
			conf = colorDim + fmt.Sprintf(" (confidence:%d%%)", r.Confidence) + colorReset
		}
		extra := ""
		if r.Extra != "" {
			extra = colorDim + " — " + r.Extra + colorReset
		}
		return fmt.Sprintf("%s %s%s%s", src, val, conf, extra)

	default:
		return fmt.Sprintf("[%s] %s", r.Type, r.Value)
	}
}

func statusCodeColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return colorGreen
	case code >= 300 && code < 400:
		return colorCyan
	case code == 401 || code == 403:
		return colorYellow
	case code >= 500:
		return colorRed
	default:
		return colorWhite
	}
}

// Progress writes a progress line using \r (overwrites current line).
// Does not add a newline, so results printed after will push it down.
func Progress(dest io.Writer, format string, args ...any) {
	fmt.Fprintf(dest, "\r"+colorDim+format+colorReset, args...)
}

// ClearProgress clears the current progress line.
func ClearProgress(dest io.Writer) {
	fmt.Fprint(dest, "\r\033[K")
}

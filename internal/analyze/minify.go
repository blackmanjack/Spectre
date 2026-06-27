package analyze

import (
	"strconv"
	"strings"
)

// isMinified heuristically detects minified source: either a very high
// average line length, or very few total lines relative to a substantial
// file size. This is a heuristic, not an exact rule — it only decides
// whether proximity checks fall back to a byte-offset window instead of a
// line-count window.
func isMinified(body string) bool {
	lines := strings.Split(body, "\n")
	if len(body) > 10*1024 && len(lines) < 5 {
		return true
	}
	if len(lines) == 0 {
		return false
	}
	avg := len(body) / len(lines)
	return avg > 500
}

// proximityWindow describes how far around a match offset to search for a
// nearby tainted-source token, and how to report the match's position back
// to a human.
type proximityWindow struct {
	minified bool
	body     string
}

func newProximityWindow(body string) proximityWindow {
	return proximityWindow{minified: isMinified(body), body: body}
}

// around returns the substring of body within the proximity window of
// offset, for tainted-source token searches.
func (w proximityWindow) around(offset int) string {
	if w.minified {
		start := offset - 200
		if start < 0 {
			start = 0
		}
		end := offset + 200
		if end > len(w.body) {
			end = len(w.body)
		}
		return w.body[start:end]
	}
	lineStart, lineEnd := lineRangeAround(w.body, offset, 5)
	return w.body[lineStart:lineEnd]
}

// position renders a human-locatable position string for a match offset:
// an approximate line number for source-form files, or a byte offset for
// minified files where line numbers are meaningless.
func (w proximityWindow) position(offset int) string {
	if w.minified {
		return "byte offset ~" + strconv.Itoa(offset)
	}
	return "line ~" + strconv.Itoa(lineNumber(w.body, offset))
}

func lineNumber(body string, offset int) int {
	if offset > len(body) {
		offset = len(body)
	}
	return strings.Count(body[:offset], "\n") + 1
}

// lineRangeAround returns the byte range covering `span` lines before and
// after the line containing offset.
func lineRangeAround(body string, offset, span int) (int, int) {
	if offset > len(body) {
		offset = len(body)
	}
	// Walk back `span` newlines from offset.
	start := offset
	newlines := 0
	for start > 0 && newlines < span {
		start--
		if body[start] == '\n' {
			newlines++
		}
	}
	if start > 0 {
		start++ // move past the newline itself
	}
	// Walk forward `span` newlines from offset.
	end := offset
	newlines = 0
	for end < len(body) && newlines < span {
		if body[end] == '\n' {
			newlines++
		}
		end++
	}
	return start, end
}

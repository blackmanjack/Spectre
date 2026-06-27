package analyze

import (
	"regexp"
	"strings"
)

type finding struct {
	category   string
	value      string
	confidence int
	position   string
	extra      string
}

var domXSSSinks = []struct {
	label string
	re    *regexp.Regexp
}{
	{"innerHTML/outerHTML assignment", regexp.MustCompile(`\.(?:innerHTML|outerHTML)\s*=`)},
	{"document.write()", regexp.MustCompile(`document\.write(?:ln)?\s*\(`)},
	{"eval()", regexp.MustCompile(`\beval\s*\(`)},
	{"setTimeout/setInterval with string callback", regexp.MustCompile(`set(?:Timeout|Interval)\s*\(\s*["']`)},
	{"insertAdjacentHTML()", regexp.MustCompile(`\.insertAdjacentHTML\s*\(`)},
	{"location assignment", regexp.MustCompile(`location\s*\.\s*(?:href|replace|assign)\s*[=(]`)},
}

var taintedSources = []string{
	"location.search", "location.hash", "URLSearchParams", "document.URL",
	"window.name", "document.referrer", "postMessage", "onmessage",
}

// scanDOMXSS finds DOM XSS sinks in body. Tier 1 (confidence ~45) flags the
// sink alone. Tier 2 (confidence ~80) upgrades the finding when a
// tainted-source token appears within the proximity window — a heuristic,
// not real taint-flow analysis, so every finding states it requires manual
// verification.
func scanDOMXSS(body string) []finding {
	var out []finding
	win := newProximityWindow(body)
	for _, sink := range domXSSSinks {
		for _, loc := range sink.re.FindAllStringIndex(body, -1) {
			offset := loc[0]
			window := win.around(offset)
			taint := ""
			for _, src := range taintedSources {
				if containsCI(window, src) {
					taint = src
					break
				}
			}
			pos := win.position(offset)
			if taint != "" {
				out = append(out, finding{
					category:   "DOM XSS sink: " + sink.label,
					value:      "DOM XSS sink: " + sink.label,
					confidence: 80,
					position:   pos,
					extra: "[tier 2: sink+taint proximity, " + pos + "] " + sink.label +
						" found near tainted source " + taint +
						" — pattern match only, not confirmed exploitable, verify data flow manually",
				})
			} else {
				out = append(out, finding{
					category:   "DOM XSS sink: " + sink.label,
					value:      "DOM XSS sink: " + sink.label,
					confidence: 45,
					position:   pos,
					extra: "[tier 1: sink only, " + pos + "] " + sink.label +
						" — no tainted source detected nearby, verify whether the value is attacker-controllable",
				})
			}
		}
	}
	return out
}

func containsCI(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

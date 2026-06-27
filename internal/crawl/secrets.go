package crawl

import "regexp"

type secretMatch struct {
	label      string
	masked     string
	confidence int
}

var secretPatterns = []struct {
	label      string
	re         *regexp.Regexp
	confidence int
}{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 90},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), 90},
	{"Stripe API Key", regexp.MustCompile(`(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}`), 90},
	{"Slack Token", regexp.MustCompile(`xox[abprs]-[0-9A-Za-z-]{10,48}`), 85},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), 60},
	{"Generic API key/secret/token assignment", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']`), 50},
}

// findSecrets scans body for credential-shaped strings. Values are masked
// (first 6 + last 4 characters) so the tool itself never echoes a full
// credential into shared output/logs. Every match requires manual
// verification before being treated as a live, exploitable credential.
func findSecrets(body string) []secretMatch {
	var out []secretMatch
	seen := make(map[string]bool)
	for _, p := range secretPatterns {
		for _, m := range p.re.FindAllString(body, -1) {
			if seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, secretMatch{label: p.label, masked: mask(m), confidence: p.confidence})
		}
	}
	return out
}

func mask(s string) string {
	if len(s) <= 12 {
		return s[:min(2, len(s))] + "…" + s[max(0, len(s)-2):]
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

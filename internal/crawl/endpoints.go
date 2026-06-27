package crawl

import "regexp"

type endpointMatch struct {
	value      string
	confidence int
	kind       string
}

var (
	absoluteURLRe  = regexp.MustCompile(`https?://[^\s"'<>)]+`)
	apiPathRe      = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql|rest)(?:/[a-zA-Z0-9_\-./{}]*)?)["']`)
	fetchCallRe    = regexp.MustCompile(`(?i)fetch\(\s*["']([^"']+)["']`)
	ajaxCallRe     = regexp.MustCompile(`(?i)\$\.(?:get|post|ajax)\(\s*["']([^"']+)["']`)
	xhrOpenRe      = regexp.MustCompile(`(?i)\.open\(\s*["']\w+["']\s*,\s*["']([^"']+)["']`)
	relativePathRe = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-./]{2,80})["']`)
)

// findEndpoints scans a body of text (HTML, JS, or CSS) for absolute URLs,
// API-looking paths, and common AJAX call argument patterns. Each match is
// reported with a confidence reflecting how specific the pattern is — a
// fetch()/$.ajax() call argument is a near-certain endpoint reference, while
// the generic relative-path fallback is a low-confidence guess that requires
// manual verification.
func findEndpoints(body string) []endpointMatch {
	var out []endpointMatch
	seen := make(map[string]bool)
	add := func(value string, confidence int, kind string) {
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, endpointMatch{value: value, confidence: confidence, kind: kind})
	}

	for _, m := range absoluteURLRe.FindAllString(body, -1) {
		add(m, 70, "absolute URL")
	}
	for _, m := range apiPathRe.FindAllStringSubmatch(body, -1) {
		add(m[1], 85, "API-looking path")
	}
	for _, m := range fetchCallRe.FindAllStringSubmatch(body, -1) {
		add(m[1], 90, "fetch() call argument")
	}
	for _, m := range ajaxCallRe.FindAllStringSubmatch(body, -1) {
		add(m[1], 90, "jQuery AJAX call argument")
	}
	for _, m := range xhrOpenRe.FindAllStringSubmatch(body, -1) {
		add(m[1], 90, "XMLHttpRequest.open() argument")
	}
	for _, m := range relativePathRe.FindAllStringSubmatch(body, -1) {
		if staticAssetExt.MatchString(m[1]) {
			continue
		}
		add(m[1], 35, "generic relative path (low confidence)")
	}
	return out
}

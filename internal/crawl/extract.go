package crawl

import "regexp"

var (
	scriptSrcRe    = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	linkHrefRe     = regexp.MustCompile(`(?i)<link[^>]+href\s*=\s*["']([^"']+)["'][^>]*>`)
	linkRelCSSRe   = regexp.MustCompile(`(?i)rel\s*=\s*["']stylesheet["']`)
	inlineScriptRe = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
	anchorHrefRe   = regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	sourceMapRe    = regexp.MustCompile(`//[#@]\s*sourceMappingURL=(\S+)`)

	staticAssetExt = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|css|mp4|mp3|pdf)(\?.*)?$`)
)

// extractAssetURLs returns script-src URLs and stylesheet link-href URLs found
// in an HTML document, plus the bodies of any inline <script> blocks.
func extractAssetURLs(html string) (scripts []string, stylesheets []string, inlineBodies []string) {
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		scripts = append(scripts, m[1])
	}
	for _, m := range linkHrefRe.FindAllString(html, -1) {
		if linkRelCSSRe.MatchString(m) {
			if href := linkHrefRe.FindStringSubmatch(m); href != nil {
				stylesheets = append(stylesheets, href[1])
			}
		}
	}
	for _, m := range inlineScriptRe.FindAllStringSubmatch(html, -1) {
		body := m[1]
		if body != "" {
			inlineBodies = append(inlineBodies, body)
		}
	}
	return scripts, stylesheets, inlineBodies
}

// extractPageLinks returns same-page-candidate <a href> targets, filtered to
// drop obvious static-asset links (images, fonts, etc.) before the caller
// applies same-origin and dedup checks.
func extractPageLinks(html string) []string {
	var out []string
	for _, m := range anchorHrefRe.FindAllStringSubmatch(html, -1) {
		href := m[1]
		if href == "" || href[0] == '#' {
			continue
		}
		if staticAssetExt.MatchString(href) {
			continue
		}
		out = append(out, href)
	}
	return out
}

// extractSourceMapRefs returns any //# sourceMappingURL= references found in
// a JS/CSS body.
func extractSourceMapRefs(body string) []string {
	var out []string
	for _, m := range sourceMapRe.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

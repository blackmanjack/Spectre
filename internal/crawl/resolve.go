package crawl

import "net/url"

// resolveURL resolves ref against base (the page's final, post-redirect URL),
// handling relative, root-relative, and protocol-relative references.
func resolveURL(base, ref string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(refURL).String(), nil
}

// sameOrigin reports whether two URLs share the same scheme+host.
func sameOrigin(a, b string) bool {
	au, err := url.Parse(a)
	if err != nil {
		return false
	}
	bu, err := url.Parse(b)
	if err != nil {
		return false
	}
	return au.Scheme == bu.Scheme && au.Host == bu.Host
}

// stripFragment removes the #fragment portion of a URL so visited-page dedup
// doesn't treat /page#a and /page#b as distinct pages.
func stripFragment(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	return u.String()
}

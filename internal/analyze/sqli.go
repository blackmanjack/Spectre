package analyze

import "regexp"

var (
	selectConcatRe = regexp.MustCompile(`(?i)["'](?:SELECT\s.+?\sFROM|INSERT\s+INTO|UPDATE\s.+?\sSET|DELETE\s+FROM)[^"']*["']\s*\+`)
	whereConcatRe  = regexp.MustCompile(`(?i)["'][^"']*\bWHERE\b[^"']*=\s*["']\s*\+`)
	classicASPRe   = regexp.MustCompile(`(?i)&\s*request\s*\([^)]*\)[^\n]{0,40}["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b`)
	execConcatRe   = regexp.MustCompile(`(?i)\bexec(?:ute)?\s*\([^)]*\+[^)]*\)`)
	sqlKeywordRe   = regexp.MustCompile(`(?i)["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']`)
	requestParamRe = regexp.MustCompile(`(?i)Request\.(?:QueryString|Form)|req\.(?:query|body)`)
	concatTokenRe  = regexp.MustCompile(`[+&]|String\.Format|%s|\{0\}`)
)

// scanSQLi looks for SQL built via string concatenation and proximity
// between SQL-keyword literals and request-parameter sources with no
// visible parameterization. Heuristic only — absence of a bind-parameter
// token nearby is treated as a signal, not proof, of missing parameterization.
func scanSQLi(body string) []finding {
	var out []finding
	win := newProximityWindow(body)

	report := func(category string, loc []int, confidence int, detail string) {
		pos := win.position(loc[0])
		out = append(out, finding{
			category:   category,
			value:      category,
			confidence: confidence,
			position:   pos,
			extra:      "[" + pos + "] " + detail,
		})
	}

	for _, loc := range selectConcatRe.FindAllStringIndex(body, -1) {
		report("SQL string concatenation", loc, 75,
			"SQL keyword string literal immediately followed by string concatenation — verify the concatenated value is parameterized, not raw user input")
	}
	for _, loc := range whereConcatRe.FindAllStringIndex(body, -1) {
		report("SQL string concatenation", loc, 75,
			"WHERE clause built via string concatenation — verify the concatenated value is parameterized, not raw user input")
	}
	for _, loc := range classicASPRe.FindAllStringIndex(body, -1) {
		report("Classic ASP unparameterized query", loc, 80,
			"Request(...) value adjacent to a SQL keyword string literal in classic ASP — verify this isn't building a query from raw request input")
	}
	for _, loc := range execConcatRe.FindAllStringIndex(body, -1) {
		report("exec()/execute() with concatenated argument", loc, 70,
			"exec()/execute() call argument contains string concatenation — verify the query is parameterized")
	}

	for _, loc := range sqlKeywordRe.FindAllStringIndex(body, -1) {
		offset := loc[0]
		window := win.around(offset)
		if requestParamRe.MatchString(window) && concatTokenRe.MatchString(window) {
			pos := win.position(offset)
			out = append(out, finding{
				category:   "SQL keyword near unparameterized request input",
				value:      "SQL keyword near unparameterized request input",
				confidence: 65,
				position:   pos,
				extra: "[" + pos + "] SQL keyword literal within proximity of a request-parameter source and a concatenation token, " +
					"with no parameterization placeholder visible nearby — absence of a bind-parameter is a heuristic signal, not proof; verify manually",
			})
		}
	}

	return out
}

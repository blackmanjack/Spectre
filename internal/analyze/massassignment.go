package analyze

import "regexp"

var (
	massPutPatchRe = regexp.MustCompile(
		`(?i)(?:fetch|axios)\s*\(\s*["'][^"']*["']\s*,\s*\{[^}]*method\s*:\s*["'](?:PUT|PATCH)["']`)
	massAxiosPutRe = regexp.MustCompile(
		`(?i)axios\.(?:put|patch)\s*\(`)
	massSensitiveFieldRe = regexp.MustCompile(
		`(?i)["'](?:dob|date_of_birth|id_number|national_id|role|is_admin|verified|kyc_status|kyc_level|admin|privilege|account_type|status|permission|superuser|owner|is_staff|is_superuser|credit_limit|balance|tier)\b["']`)
	massHiddenInputRe = regexp.MustCompile(
		`(?i)<input[^>]+type=["']hidden["'][^>]*name=["'](?:role|is_admin|admin|privilege|kyc_status|kyc_level|verified|account_type|permission|status|superuser)["']`)
)

func scanMassAssignment(body string) []finding {
	var out []finding
	win := newProximityWindow(body)

	// PUT/PATCH calls
	for _, re := range []*regexp.Regexp{massPutPatchRe, massAxiosPutRe} {
		for _, loc := range re.FindAllStringIndex(body, -1) {
			offset := loc[0]
			window := win.around(offset)
			pos := win.position(offset)

			hasSensitiveField := massSensitiveFieldRe.MatchString(window)
			confidence := 55
			detail := "PUT/PATCH endpoint detected — check whether server accepts and persists unexpected fields"
			if hasSensitiveField {
				confidence = 75
				detail = "PUT/PATCH endpoint + privileged/sensitive field name detected nearby — possible mass assignment vulnerability"
			}

			out = append(out, finding{
				category:   "Mass assignment",
				value:      "Mass assignment",
				confidence: confidence,
				position:   pos,
				extra: "[tier " + tierLabel(confidence) + ", " + pos + "] " + detail +
					" — pattern match only, replay with extra privileged fields and confirm server persistence",
			})
		}
	}

	// Hidden input with privileged field name (direct hit)
	for _, loc := range massHiddenInputRe.FindAllStringIndex(body, -1) {
		offset := loc[0]
		pos := win.position(offset)
		out = append(out, finding{
			category:   "Mass assignment",
			value:      "Mass assignment",
			confidence: 75,
			position:   pos,
			extra: "[tier 2, " + pos + "] hidden form input with privileged field name" +
				" — check whether the field is accepted and persisted by the server without authorization",
		})
	}
	return out
}

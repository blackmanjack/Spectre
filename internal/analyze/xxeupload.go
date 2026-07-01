package analyze

import "regexp"

var (
	xxeFileInputRe     = regexp.MustCompile(`(?i)<input[^>]+type=["']file["'][^>]*accept=["'][^"']*\.(?:xlsx|xls|xml|docx|odt|ods)[^"']*["']`)
	xxeFileInputLooseRe = regexp.MustCompile(`(?i)<input[^>]+type=["']file["']`)
	xxeEndpointRe      = regexp.MustCompile(`(?i)(?:fetch|axios|XMLHttpRequest|\.open)\s*\(\s*["'][^"']*(?:upload|import|combine|parse|process|ingest)[^"']*["']`)
	xxeServerMimeRe    = regexp.MustCompile(`(?i)(?:application/(?:xml|vnd\.openxmlformats|vnd\.ms-excel|spreadsheet)|text/xml)`)
	xxeProcessingPathRe = regexp.MustCompile(`(?i)["'/](?:parseExcel|importSpreadsheet|parseXML|processUpload|xlsxParser|xlsxImport)[/"']?`)
)

func scanXXEUpload(body string) []finding {
	var out []finding
	win := newProximityWindow(body)

	fileInputRe := xxeFileInputRe
	tier1Re := xxeFileInputLooseRe

	for _, re := range []*regexp.Regexp{fileInputRe, tier1Re, xxeEndpointRe} {
		for _, loc := range re.FindAllStringIndex(body, -1) {
			offset := loc[0]
			window := win.around(offset)
			pos := win.position(offset)

			hasSpreadsheetAccept := xxeFileInputRe.MatchString(window)
			hasUploadEndpoint := xxeEndpointRe.MatchString(window)
			hasXMLMime := xxeServerMimeRe.MatchString(window)
			hasProcessingPath := xxeProcessingPathRe.MatchString(window)
			upgradeSignal := hasXMLMime || hasProcessingPath

			confidence := 0
			detail := ""
			switch {
			case hasSpreadsheetAccept && (hasUploadEndpoint || upgradeSignal):
				confidence = 75
				detail = "file input accepting spreadsheet/XML extension + upload endpoint or XML MIME type detected nearby — server likely parses XML content"
			case hasSpreadsheetAccept:
				confidence = 60
				detail = "file input accepting spreadsheet/XML extension — check whether server parses XML content from the uploaded file"
			case hasUploadEndpoint && upgradeSignal:
				confidence = 65
				detail = "upload endpoint + XML processing signal (MIME type or parsing function name) detected"
			case hasUploadEndpoint:
				confidence = 55
				detail = "upload/import endpoint detected — check for XML/OOXML server-side parsing"
			}

			if confidence == 0 {
				continue
			}

			// deduplicate: skip if we already have a higher-confidence finding at same position
			dup := false
			for _, existing := range out {
				if existing.position == pos && existing.confidence >= confidence {
					dup = true
					break
				}
			}
			if dup {
				continue
			}

			out = append(out, finding{
				category:   "XXE via file upload",
				value:      "XXE via file upload",
				confidence: confidence,
				position:   pos,
				extra: "[tier " + tierLabel(confidence) + ", " + pos + "] " + detail +
					" — pattern match only, verify whether server parses XML entities from upload content",
			})
			break // one finding per outer-loop iteration is enough
		}
	}
	return out
}

func tierLabel(conf int) string {
	if conf >= 70 {
		return "2"
	}
	return "1"
}

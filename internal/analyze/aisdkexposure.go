package analyze

import "regexp"

var (
	geminiSDKInitRe = regexp.MustCompile(
		`(?i)new\s+GoogleGenerativeAI\s*\(`)
	geminiWSRe = regexp.MustCompile(
		`(?i)wss?://[^"']*generativelanguage\.googleapis\.com`)
	aiSDKInitRe = regexp.MustCompile(
		`(?i)new\s+(?:Anthropic|OpenAI|VertexAI|AzureOpenAI|CohereClient|MistralClient|BedrockRuntimeClient)\s*\(\s*\{[^}]*(?:apiKey|api_key|accessKeyId|token)\s*:`)
	globalCredGetterRe = regexp.MustCompile(
		`(?i)(?:window|globalThis)\s*\.\s*(?:get[A-Z][A-Za-z]*Token|getJWTToken|getTempAWS[A-Za-z]*|getGemini[A-Za-z]*|getAI[A-Za-z]*Creds?)\s*=\s*(?:async\s+)?function`)
	ephemeralTokenFetchRe = regexp.MustCompile(
		`(?i)fetch\s*\(\s*["'][^"']*(?:token|ephemeral|live.connect|session|credential)[^"']*["']`)
	tokenConstraintPresentRe = regexp.MustCompile(
		`(?i)(?:bidi_generate_content_setup|live_connect_constraints|allowed_models|system_instruction)`)
)

func scanAISDKExposure(body string) []finding {
	var out []finding
	win := newProximityWindow(body)

	type check struct {
		re         *regexp.Regexp
		baseConf   int
		category   string
		detail     string
		boostOnWS  bool
		penalizeIfConstraint bool
	}

	checks := []check{
		{
			re:       geminiSDKInitRe,
			baseConf: 70,
			category: "AI SDK client-side credential exposure",
			detail:   "GoogleGenerativeAI SDK initialized in client-side JS — API key may be exposed to end users",
		},
		{
			re:                   geminiWSRe,
			baseConf:             85,
			category:             "AI SDK client-side credential exposure",
			detail:               "WebSocket to Gemini Live API detected in client-side code — ephemeral token may lack live_connect_constraints",
			penalizeIfConstraint: true,
		},
		{
			re:       aiSDKInitRe,
			baseConf: 70,
			category: "AI SDK client-side credential exposure",
			detail:   "AI SDK (OpenAI/Anthropic/Vertex/etc.) initialized with credential in client-side code",
		},
		{
			re:       globalCredGetterRe,
			baseConf: 75,
			category: "AI SDK client-side credential exposure",
			detail:   "Globally callable credential getter exposed on window/globalThis — credentials callable from any script on the page",
		},
		{
			re:                   ephemeralTokenFetchRe,
			baseConf:             75,
			category:             "AI SDK client-side credential exposure",
			detail:               "Ephemeral/session token endpoint fetched client-side — verify token includes live_connect_constraints to prevent prompt injection",
			penalizeIfConstraint: true,
		},
	}

	for _, c := range checks {
		for _, loc := range c.re.FindAllStringIndex(body, -1) {
			offset := loc[0]
			window := win.around(offset)
			pos := win.position(offset)

			conf := c.baseConf
			detail := c.detail
			if c.penalizeIfConstraint && tokenConstraintPresentRe.MatchString(window) {
				// Constraint field visible nearby — reduces risk, lower confidence
				conf -= 20
				detail += " (constraint field detected nearby — verify constraints are actually enforced)"
			}
			if conf < 50 {
				continue
			}

			out = append(out, finding{
				category:   c.category,
				value:      c.category,
				confidence: conf,
				position:   pos,
				extra: "[tier " + tierLabel(conf) + ", " + pos + "] " + detail +
					" — pattern match only, verify in Network tab whether credentials are sent to/from the browser",
			})
		}
	}
	return out
}

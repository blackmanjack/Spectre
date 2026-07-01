package analyze

import "strings"

// howToTest returns concrete manual verification steps for a finding
// category, framed explicitly as "next step to confirm," never as exploit
// generation. Returns "" for categories with no authored guidance yet —
// callers must treat that as "no guidance available," not an error.
func howToTest(category string) string {
	switch {
	case strings.Contains(category, "innerHTML"), strings.Contains(category, "outerHTML"),
		strings.Contains(category, "insertAdjacentHTML"), strings.Contains(category, "document.write"):
		return domXSSHTMLSinkGuidance
	case strings.Contains(category, "location assignment"):
		return domXSSLocationGuidance
	case strings.Contains(category, "eval()"), strings.Contains(category, "setTimeout"), strings.Contains(category, "setInterval"):
		return domXSSEvalGuidance
	case strings.Contains(category, "Hardcoded credential"):
		return hardcodedCredGuidance
	case strings.Contains(category, "SQL"), strings.Contains(category, "unparameterized"),
		strings.Contains(category, "ASP") && strings.Contains(category, "SQL"):
		return sqliConcatGuidance
	case strings.Contains(category, "ValidateRequest"), strings.Contains(category, "AllowAnonymous"),
		strings.Contains(category, "role check"), strings.Contains(category, "auth check"):
		return authBypassGuidance
	case strings.Contains(category, "XXE"):
		return xxeUploadGuidance
	case strings.Contains(category, "Mass assignment"):
		return massAssignmentGuidance
	case strings.Contains(category, "Open redirect"), strings.Contains(category, "javascript: URI"):
		return openRedirectGuidance
	case strings.Contains(category, "AI SDK"), strings.Contains(category, "Gemini"), strings.Contains(category, "ephemeral token"):
		return aiSDKExposureGuidance
	default:
		return ""
	}
}

const domXSSHTMLSinkGuidance = `How to test (manual verification, not an automated exploit):
1. Open browser devtools, set a breakpoint at the reported sink position.
2. Trace what value flows into the sink back to its origin (variables, function args, returns).
3. If the origin is location.search/location.hash/postMessage/document.referrer: load the page
   with a benign marker (e.g. ?test=XSSMARKER123) in that source and confirm the marker reaches
   the breakpoint unmodified and unescaped.
4. Only in an authorized test environment, replace the marker with a minimal HTML probe
   (e.g. <img src=x onerror=alert(document.domain)>) and confirm execution.
5. Check for a Content-Security-Policy response header that could block inline execution even
   if the data flow is real — note its presence/absence in your finding writeup.
This confirms or refutes the finding; it is not a delivered exploit.`

const domXSSLocationGuidance = `How to test (manual verification, not an automated exploit):
1. Set a breakpoint on the location.href/replace/assign call at the reported position.
2. From the browser console (or a local test page you control), send a postMessage to the
   target window and confirm whether your message data reaches this code path.
3. Check whether the code validates event.origin before acting on event.data — a missing
   origin check plus untrusted data reaching a location assignment is what makes this
   exploitable (open redirect or javascript: URI injection, depending on scheme handling).
4. Confirm with a benign, same-origin redirect target via postMessage — do not test with an
   external/malicious target outside an authorized environment.`

const domXSSEvalGuidance = `How to test (manual verification, not an automated exploit):
1. Set a breakpoint at the reported eval()/setTimeout()/setInterval() call.
2. Trace the string argument back to its source — confirm whether any part of it is
   attacker-controllable (URL, postMessage, stored data later rendered here).
3. If controllable, test with a benign marker string first to confirm it reaches eval()
   unmodified before considering anything further.
4. Note that even a confirmed reachable eval() may not be practically exploitable if the
   controllable portion is constrained (e.g. only a numeric ID) — check the actual
   constraints before concluding this is exploitable.`

const hardcodedCredGuidance = `How to test (manual verification, not an automated exploit):
1. Check git history for this line (when added, by whom) and check whether the same value
   appears in a .env.example/test-fixture elsewhere in the repo — a strong signal it's a
   placeholder, not a live credential.
2. If it looks live, do not use it against any system without explicit authorization — report
   it through the engagement's disclosure channel for rotation instead.
3. If authorized to verify, attempt authentication using a read-only, non-destructive method
   against the specific service this credential appears to target.`

const sqliConcatGuidance = `How to test (manual verification, not an automated exploit):
1. Trace the request parameter(s) flowing into the concatenated string back to their source
   (query string, form field, header).
2. In an authorized test environment only, send a single quote (') as that parameter's value
   and compare the response/error against a baseline request.
3. If the response differs, follow up with a boolean-based pair (' OR '1'='1 vs ' OR '1'='2)
   and confirm the response differs in the expected direction.
4. Do not proceed to data extraction or automated SQLi tooling without separate written
   authorization for that level of testing.`

const xxeUploadGuidance = `How to test (manual verification, not an automated exploit):
1. Download a sample XLSX file and unzip it (XLSX is a ZIP archive).
2. Open xl/worksheets/sheet1.xml and inject a DOCTYPE + external entity before the <worksheet> tag:
     <?xml version="1.0"?>
     <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   Then reference it in a cell: <v>&xxe;</v>
3. Re-zip the directory structure back into a .xlsx file (preserving paths).
4. Upload the modified file through the identified endpoint.
5. Check the response or any subsequent data display for /etc/passwd content.
6. For blind XXE, use an out-of-band collaborator URL (e.g. Burp Collaborator) in the SYSTEM identifier.
7. On Windows targets, substitute "file:///C:/windows/win.ini" as an initial probe.
This confirms or refutes whether the server parses XML entities from uploaded file content.`

const massAssignmentGuidance = `How to test (manual verification, not an automated exploit):
1. Capture a normal PUT or PATCH request to the endpoint in a proxy (Burp/mitmproxy).
2. Note the fields in the original request body (e.g. {"name":"John","email":"john@example.com"}).
3. Add privileged/sensitive fields that are NOT in the original request:
     {"name":"John","email":"john@example.com","role":"admin","is_admin":true,"kyc_status":"verified"}
4. Send the modified request and note the HTTP response.
5. Follow up with a GET request to the same resource and inspect whether the added fields were persisted.
6. If persisted, document the before/after field values — this confirms mass assignment.
7. Do not escalate beyond read access (e.g. do not use the gained role to access other accounts).`

const openRedirectGuidance = `How to test (manual verification, not an automated exploit):
1. Identify the redirect parameter name from the finding (e.g. ?redirect=, ?next=, ?url=).
2. Test with a benign external domain first: ?redirect=https://example.com — confirm whether the
   server/client actually follows this redirect to the external domain.
3. If open redirect confirmed, test the javascript: scheme: ?redirect=javascript:alert(document.domain)
   — confirm whether this results in script execution in the target origin.
4. For window.name-based smuggling: open attacker page that sets window.name to a payload,
   then navigates the victim tab to the target — confirm whether the payload reaches the sink.
5. Check if the redirect destination is validated server-side (allowlist, same-origin check).
6. Document the full navigation chain — do not redirect to attacker infrastructure outside an
   authorized environment.`

const aiSDKExposureGuidance = `How to test (manual verification, not an automated exploit):
1. Open browser DevTools → Network tab. Filter by the AI provider domain
   (e.g. generativelanguage.googleapis.com, api.openai.com, api.anthropic.com).
2. Inspect request/response payloads for API keys, JWT tokens, or session credentials.
3. If a token endpoint is detected: fetch its response and inspect for live_connect_constraints
   (Gemini Live) or equivalent scope-limiting fields.
4. Call any globally exposed getter from the console: window.getJWTToken() — note the returned value.
5. To confirm a key is live (not a placeholder), make a single minimal read-only API call
   (e.g. list models, not generate content) using the credential.
6. For Gemini Live: check whether the token's bidi_generate_content_setup allows arbitrary
   system_instruction injection — inject a benign test instruction and confirm it takes effect.
7. Never go beyond validating key/constraint status; do not use the credential for data access
   or model abuse outside the authorized test scope.`

const authBypassGuidance = `How to test (manual verification, not an automated exploit):
1. For a client-side-only role check: attempt the gated action with devtools open and the
   check bypassed/patched client-side (e.g. via a breakpoint that skips the branch) — if the
   server still permits the action, authorization is missing server-side, which is the real
   vulnerability (the client-side check alone proves nothing about server enforcement).
2. For ValidateRequest="false"/AllowAnonymous: submit a request to the affected endpoint with
   an unauthenticated session (or a raw HTML/script payload, if testing ValidateRequest) and
   confirm whether the server processes it without the expected validation/authentication.
3. Document the server's actual behavior, not just the source-code indicator — the annotation
   alone is a signal, not proof of an exploitable gap.`

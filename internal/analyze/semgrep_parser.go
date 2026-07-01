package analyze

import (
	"encoding/json"
	"fmt"
)

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Metadata struct {
			Category string `json:"category"`
			// Engine is set by SPECTRE's own embedded rules to "taint" for
			// rules written in taint mode, so we can distinguish them from
			// plain search-mode rules without relying on dataflow_trace (a
			// Semgrep Pro-only field not available in the OSS engine).
			Engine string `json:"engine"`
		} `json:"metadata"`
	} `json:"extra"`
}

// semgrepFinding pairs a finding with the file path semgrep reported it
// against, since one semgrep invocation can cover many files in one Run().
type semgrepFinding struct {
	f    finding
	path string
}

// parseSemgrepJSON maps semgrep's --json output into the shared finding
// shape. Findings with a dataflow_trace (confirmed taint flow) get
// confidence 95 — deliberately above the regex scanners' max of 90, since
// this is the strongest evidence tier SPECTRE can produce. Pattern-only
// semgrep matches (no dataflow trace) get confidence 70, below regex
// tier-2's 80, since an AST-aware pattern match without confirmed data flow
// is not meaningfully stronger evidence than the regex proximity heuristic.
func parseSemgrepJSON(data []byte) ([]semgrepFinding, error) {
	var out semgrepOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	var findings []semgrepFinding
	for _, r := range out.Results {
		category := r.Extra.Metadata.Category
		if category == "" {
			category = r.CheckID // fallback for externally-supplied rulesets with no category metadata
		}
		// Rules authored by SPECTRE set metadata.engine = "taint" for
		// taint-mode rules. This lets us give confidence 95 (taint-tracking
		// is running) vs 70 (plain pattern match) without relying on
		// dataflow_trace, which is a Semgrep Pro-only field not emitted by
		// the OSS engine even when taint analysis is active.
		confidence := 70
		tag := "[semgrep:pattern]"
		if r.Extra.Metadata.Engine == "taint" {
			confidence = 95
			tag = "[semgrep:taint-mode]"
		}
		pos := fmt.Sprintf("line %d-%d", r.Start.Line, r.End.Line)
		findings = append(findings, semgrepFinding{
			f: finding{
				category:   "[semgrep] " + category,
				value:      "[semgrep] " + category,
				confidence: confidence,
				position:   pos,
				extra:      tag + " " + r.Extra.Message + " (" + pos + ")",
			},
			path: r.Path,
		})
	}
	return findings, nil
}

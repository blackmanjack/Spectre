package dirfuzz

import "bytes"

// FilterConfig holds all response exclusion/inclusion rules.
type FilterConfig struct {
	StatusFilter []int    // if non-empty, SHOW only these codes
	StatusExcl   []int    // exclude these codes
	SizeExcl     []int64  // exclude exact sizes
	BodyExcl     string   // exclude if body contains this string
	Soft404Body  []byte   // soft-404 fingerprint body to exclude
	Soft404Size  int64    // soft-404 size fingerprint
}

// ProbeResult holds the outcome of one HTTP probe.
type ProbeResult struct {
	Path   string
	Status int
	Size   int64
	Words  int
	Lines  int
	Body   []byte // first 4KB for matching
}

// ShouldShow returns true if the result passes all filters and should be printed.
func ShouldShow(r ProbeResult, cfg FilterConfig) bool {
	// Status allowlist takes priority
	if len(cfg.StatusFilter) > 0 {
		if !intContains(cfg.StatusFilter, r.Status) {
			return false
		}
	} else if intContains(cfg.StatusExcl, r.Status) {
		return false
	}

	// Size exclusion
	for _, sz := range cfg.SizeExcl {
		if r.Size == sz {
			return false
		}
	}

	// Body exclusion
	if cfg.BodyExcl != "" && bytes.Contains(r.Body, []byte(cfg.BodyExcl)) {
		return false
	}

	// Soft-404 detection: exclude if body matches fingerprint
	if len(cfg.Soft404Body) > 0 && len(r.Body) > 0 {
		// Compare first 256 bytes as fingerprint
		fp := cfg.Soft404Body
		rb := r.Body
		if len(fp) > 256 {
			fp = fp[:256]
		}
		if len(rb) > 256 {
			rb = rb[:256]
		}
		if bytes.Equal(fp, rb) {
			return false
		}
	}
	if cfg.Soft404Size > 0 && r.Size == cfg.Soft404Size {
		return false
	}

	return true
}

func intContains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

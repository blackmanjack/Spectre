package portscan

import (
	"bufio"
	"io/fs"
	"net"
	"strconv"
	"strings"
)

// OSFingerprint represents one entry in the OS fingerprint database.
type OSFingerprint struct {
	Name       string
	TTL        int
	WindowSize int
	TCPOptions string
}

// OSDatabase holds the loaded OS fingerprints.
type OSDatabase struct {
	fingerprints []OSFingerprint
}

// LoadOSDB parses os-fingerprints.txt from the embedded FS.
func LoadOSDB(embedded fs.FS) *OSDatabase {
	f, err := embedded.Open("os-fingerprints.txt")
	if err != nil {
		return &OSDatabase{}
	}
	defer f.Close()

	db := &OSDatabase{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: OS "name" TTL <ttl> WIN <win> OPTS "<opts>"
		fp := parseOSLine(line)
		if fp != nil {
			db.fingerprints = append(db.fingerprints, *fp)
		}
	}
	return db
}

// Match returns the best-matching OS and confidence given observed TTL and window size.
func (db *OSDatabase) Match(ttl, windowSize int) (string, int) {
	if len(db.fingerprints) == 0 {
		return guessOSByTTL(ttl), 50
	}

	bestName := ""
	bestScore := 0

	for _, fp := range db.fingerprints {
		score := 0
		// TTL match (allow ±5 variance for hop reduction)
		if ttl > 0 && abs(fp.TTL-ttl) <= 5 {
			score += 50
		}
		// Window size exact match
		if windowSize > 0 && fp.WindowSize == windowSize {
			score += 40
		}
		// Partial window (same class)
		if windowSize > 0 && fp.WindowSize > 0 && sameWindowClass(fp.WindowSize, windowSize) {
			score += 20
		}
		if score > bestScore {
			bestScore = score
			bestName = fp.Name
		}
	}

	if bestName == "" {
		return guessOSByTTL(ttl), 40
	}
	confidence := min(bestScore, 95)
	return bestName, confidence
}

func guessOSByTTL(ttl int) string {
	switch {
	case ttl <= 64:
		return "Linux/Unix/macOS"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Network Device (Cisco/Juniper)"
	default:
		return "Unknown"
	}
}

func sameWindowClass(a, b int) bool {
	classify := func(w int) string {
		switch {
		case w <= 8192:
			return "small"
		case w <= 32768:
			return "medium"
		default:
			return "large"
		}
	}
	return classify(a) == classify(b)
}

func parseOSLine(line string) *OSFingerprint {
	var fp OSFingerprint
	// Simple tokenizer for: OS "Linux 4.x/5.x" TTL 64 WIN 29200 OPTS "..."
	parts := strings.Fields(line)
	if len(parts) < 6 || parts[0] != "OS" {
		return nil
	}
	// Name (may have spaces if quoted across fields, but Fields splits them)
	// Find quoted name
	nameStart := strings.Index(line, `"`)
	nameEnd := strings.Index(line[nameStart+1:], `"`)
	if nameStart < 0 || nameEnd < 0 {
		return nil
	}
	fp.Name = line[nameStart+1 : nameStart+1+nameEnd]
	rest := line[nameStart+1+nameEnd+1:]
	fields := strings.Fields(rest)
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "TTL":
			fp.TTL, _ = strconv.Atoi(fields[i+1])
		case "WIN":
			fp.WindowSize, _ = strconv.Atoi(fields[i+1])
		case "OPTS":
			opts := strings.Trim(fields[i+1], `"`)
			fp.TCPOptions = opts
		}
	}
	if fp.Name == "" || fp.TTL == 0 {
		return nil
	}
	return &fp
}

// PassiveOSDetect tries to infer OS from observed TCP parameters without sending probes.
// ttl and windowSize come from the SYN-ACK packet received during discovery.
func PassiveOSDetect(db *OSDatabase, ttl, windowSize int) OSResult {
	if ttl == 0 {
		return OSResult{}
	}
	// Adjust TTL for typical hop reduction (subtract up to 10 hops)
	// Most targets are within 10 hops — infer original TTL
	inferredTTL := ttl
	for _, initial := range []int{64, 128, 255} {
		if ttl <= initial && initial-ttl <= 15 {
			inferredTTL = initial
			break
		}
	}

	name, conf := db.Match(inferredTTL, windowSize)
	return OSResult{
		Name:       name,
		Confidence: conf,
		TTL:        ttl,
		WindowSize: windowSize,
		Method:     "passive",
	}
}

// MeasureTCPParams dials the target and extracts TTL+window from the response.
// This is a best-effort passive observation during the connect phase.
func MeasureTCPParams(target string, port int) (ttl, windowSize int) {
	// On most systems we can't easily get TTL from net.Conn.
	// We do a basic connect and check RemoteAddr. The actual TTL requires
	// raw sockets or packet capture. Return 0 if not available.
	conn, err := net.DialTimeout("tcp", target+":"+strconv.Itoa(port), 2e9)
	if err != nil {
		return 0, 0
	}
	conn.Close()
	// TTL not accessible via standard net.Conn; return 0 for passive detection
	return 0, 0
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

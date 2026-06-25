package evasion

import (
	"math/rand"
	"time"
)

// TimingTemplate defines scan timing parameters for IDS/IPS evasion.
type TimingTemplate struct {
	Name        string
	MinDelay    time.Duration
	MaxDelay    time.Duration
	Concurrency int
	Description string
}

// Templates maps T0-T5 and named templates to their parameters.
var Templates = map[string]TimingTemplate{
	"T0": {Name: "paranoid", MinDelay: 5 * time.Minute, MaxDelay: 10 * time.Minute, Concurrency: 1,
		Description: "Extremely slow — evades most IDS logging"},
	"T1": {Name: "sneaky", MinDelay: 15 * time.Second, MaxDelay: 30 * time.Second, Concurrency: 2,
		Description: "Very slow — stealthy against threshold-based IDS"},
	"T2": {Name: "polite", MinDelay: 400 * time.Millisecond, MaxDelay: 2 * time.Second, Concurrency: 10,
		Description: "Polite — reduces load on target"},
	"T3": {Name: "normal", MinDelay: 10 * time.Millisecond, MaxDelay: 100 * time.Millisecond, Concurrency: 50,
		Description: "Balanced (default Nmap)"},
	"T4": {Name: "aggressive", MinDelay: 1 * time.Millisecond, MaxDelay: 10 * time.Millisecond, Concurrency: 500,
		Description: "Fast — assumes reliable network"},
	"T5": {Name: "insane", MinDelay: 0, MaxDelay: 1 * time.Millisecond, Concurrency: 5000,
		Description: "Maximum speed — high false-positive risk on lossy networks"},
	"paranoid":   {Name: "paranoid", MinDelay: 5 * time.Minute, MaxDelay: 10 * time.Minute, Concurrency: 1},
	"sneaky":     {Name: "sneaky", MinDelay: 15 * time.Second, MaxDelay: 30 * time.Second, Concurrency: 2},
	"polite":     {Name: "polite", MinDelay: 400 * time.Millisecond, MaxDelay: 2 * time.Second, Concurrency: 10},
	"normal":     {Name: "normal", MinDelay: 10 * time.Millisecond, MaxDelay: 100 * time.Millisecond, Concurrency: 50},
	"aggressive": {Name: "aggressive", MinDelay: 1 * time.Millisecond, MaxDelay: 10 * time.Millisecond, Concurrency: 500},
	"insane":     {Name: "insane", MinDelay: 0, MaxDelay: 1 * time.Millisecond, Concurrency: 5000},
}

// GetTemplate returns the timing template or a sensible default.
func GetTemplate(name string) TimingTemplate {
	if t, ok := Templates[name]; ok {
		return t
	}
	return Templates["T4"] // default: aggressive
}

// Jitter returns a random delay within the template's range.
// Use this before each probe to randomize cadence and avoid fixed-signature detection.
func Jitter(t TimingTemplate) time.Duration {
	if t.MaxDelay <= t.MinDelay {
		return t.MinDelay
	}
	rang := int64(t.MaxDelay - t.MinDelay)
	return t.MinDelay + time.Duration(rand.Int63n(rang))
}

// ShuffleInts randomizes probe order so there's no sequential sweep signature.
func ShuffleInts(s []int) {
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

// ShuffleStrings randomizes string slice order.
func ShuffleStrings(s []string) {
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

// RandomSourcePort returns a random high-numbered source port
// to avoid fixed source-port signature detection.
func RandomSourcePort() int {
	return rand.Intn(55534) + 10001 // 10001-65535
}

// DecoyList parses a decoy spec "-D ip1,ip2,ME" into a list of IPs.
// "ME" is replaced with the actual source IP placeholder.
func DecoyList(spec string) []string {
	if spec == "" {
		return nil
	}
	var decoys []string
	for _, d := range splitDecoys(spec) {
		d = trimSpace(d)
		if d != "" {
			decoys = append(decoys, d)
		}
	}
	return decoys
}

func splitDecoys(s string) []string {
	var parts []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			parts = append(parts, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

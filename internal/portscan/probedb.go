package portscan

import (
	"bufio"
	"io/fs"
	"regexp"
	"strings"
)

// ServiceProbe represents one entry from the service-probes database.
type ServiceProbe struct {
	Name     string
	Protocol string // TCP or UDP
	Send     string // probe data to send (empty = listen for banner)
	Matches  []ProbeMatch
	Ports    []int
}

// ProbeMatch holds one match rule from the probe database.
type ProbeMatch struct {
	Service  string
	Pattern  *regexp.Regexp
	Version  string // version template (e.g. "$1")
	Soft     bool   // true = softmatch (lower confidence)
}

// ProbeDB holds all parsed service probes indexed for quick lookup.
type ProbeDB struct {
	probes    []ServiceProbe
	portIndex map[int][]int // port -> slice of probe indices
}

// LoadProbeDB parses service-probes.txt from the embedded FS.
func LoadProbeDB(embedded fs.FS) (*ProbeDB, error) {
	f, err := embedded.Open("service-probes.txt")
	if err != nil {
		return &ProbeDB{portIndex: make(map[int][]int)}, nil
	}
	defer f.Close()

	db := &ProbeDB{portIndex: make(map[int][]int)}
	var current *ServiceProbe

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "PROBE ") {
			if current != nil {
				db.probes = append(db.probes, *current)
			}
			parts := strings.Fields(line)
			if len(parts) < 3 {
				current = nil
				continue
			}
			send := ""
			if len(parts) >= 4 {
				send = unquote(strings.Join(parts[3:], " "))
			}
			current = &ServiceProbe{
				Protocol: parts[1],
				Name:     parts[2],
				Send:     send,
			}
		} else if strings.HasPrefix(line, "MATCH ") && current != nil {
			m := parseMatch(line, false)
			if m != nil {
				current.Matches = append(current.Matches, *m)
			}
		} else if strings.HasPrefix(line, "SOFTMATCH ") && current != nil {
			m := parseMatch(line, true)
			if m != nil {
				current.Matches = append(current.Matches, *m)
			}
		}
	}
	if current != nil {
		db.probes = append(db.probes, *current)
	}
	return db, scanner.Err()
}

// Match attempts to identify a service from a banner.
// Returns (service, version, confidence).
func (db *ProbeDB) Match(banner []byte) (string, string, int) {
	for _, probe := range db.probes {
		for _, m := range probe.Matches {
			if m.Pattern == nil {
				continue
			}
			groups := m.Pattern.FindSubmatch(banner)
			if groups == nil {
				continue
			}
			version := expandVersion(m.Version, groups)
			confidence := 90
			if m.Soft {
				confidence = 60
			}
			return m.Service, version, confidence
		}
	}
	return "", "", 0
}

// ProbesFor returns all probes relevant for a given port.
func (db *ProbeDB) ProbesFor(port int) []ServiceProbe {
	// Always include the NULL probe (grab banner without sending)
	var result []ServiceProbe
	for _, p := range db.probes {
		if p.Name == "NULL" || containsPort(p.Ports, port) {
			result = append(result, p)
		}
	}
	return result
}

func parseMatch(line string, soft bool) *ProbeMatch {
	// Format: MATCH <service> m|<pattern>| [v|<template>|]
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}
	service := fields[1]
	patternField := fields[2]

	// Extract pattern between delimiters (e.g. m|...|)
	if len(patternField) < 3 || patternField[0] != 'm' {
		return nil
	}
	delim := patternField[1]
	rest := patternField[2:]
	end := strings.IndexByte(rest, delim)
	if end < 0 {
		return nil
	}
	patStr := rest[:end]

	re, err := regexp.Compile("(?i)(?s)" + patStr)
	if err != nil {
		return nil
	}

	version := ""
	for _, f := range fields[3:] {
		if len(f) >= 3 && f[0] == 'v' {
			d := f[1]
			r := f[2:]
			e := strings.IndexByte(r, d)
			if e >= 0 {
				version = r[:e]
			}
		}
	}

	return &ProbeMatch{
		Service: service,
		Pattern: re,
		Version: version,
		Soft:    soft,
	}
}

func expandVersion(tmpl string, groups [][]byte) string {
	if tmpl == "" || len(groups) == 0 {
		return ""
	}
	result := tmpl
	for i, g := range groups[1:] {
		placeholder := "$" + string(rune('1'+i))
		result = strings.ReplaceAll(result, placeholder, string(g))
	}
	return result
}

func unquote(s string) string {
	s = strings.Trim(s, `"`)
	return strings.ReplaceAll(s, `\r\n`, "\r\n")
}

func containsPort(ports []int, p int) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}

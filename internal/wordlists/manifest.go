package wordlists

import (
	_ "embed"
	"encoding/json"
)

//go:embed manifest.json
var manifestData []byte

// Entry describes one wordlist in the catalog.
type Entry struct {
	Name    string   `json:"name"`
	Tags    []string `json:"tags"`    // category, size, source
	URL     string   `json:"url"`
	License string   `json:"license"`
	SHA256  string   `json:"sha256"`
	Size    string   `json:"size"`
	Desc    string   `json:"desc"`
}

// Catalog is the full list of available wordlists.
type Catalog struct {
	Lists []Entry `json:"lists"`
}

// LoadCatalog returns the embedded wordlist catalog.
func LoadCatalog() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(manifestData, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ByName returns the entry with the given name, or nil.
func (c *Catalog) ByName(name string) *Entry {
	for i := range c.Lists {
		if c.Lists[i].Name == name {
			return &c.Lists[i]
		}
	}
	return nil
}

// ByTags returns all entries whose Tags contain ALL of the given tags.
func (c *Catalog) ByTags(tags ...string) []Entry {
	var out []Entry
	for _, e := range c.Lists {
		if hasAllTags(e.Tags, tags) {
			out = append(out, e)
		}
	}
	return out
}

func hasAllTags(have, want []string) bool {
	m := make(map[string]bool, len(have))
	for _, t := range have {
		m[t] = true
	}
	for _, t := range want {
		if !m[t] {
			return false
		}
	}
	return true
}

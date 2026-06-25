package plugin

import (
	"context"
	"fmt"
	"sort"

	"github.com/spectre-tool/spectre/internal/output"
)

// Plugin is the interface all SPECTRE plugins must implement.
// Plugins extend the core without modifying it.
type Plugin interface {
	Name() string
	Description() string
	Run(ctx context.Context, target string, opts map[string]any, out output.Writer) error
}

// Registry holds all registered plugins.
var Registry = map[string]Plugin{}

// Register adds a plugin to the registry. Call from init() in plugin packages.
func Register(p Plugin) {
	Registry[p.Name()] = p
}

// List returns plugin names sorted alphabetically.
func List() []string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Get retrieves a plugin by name.
func Get(name string) (Plugin, error) {
	p, ok := Registry[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found — run `spectre plugin list`", name)
	}
	return p, nil
}

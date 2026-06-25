package wordlists

import "embed"

// FS holds the small curated default wordlists bundled into the binary.
// These are our own curated lists (our license). Third-party lists are
// fetched on-demand by `spectre wordlists pull` — never redistributed here.
//
//go:embed subdomains.txt directories.txt service-probes.txt os-fingerprints.txt
var FS embed.FS

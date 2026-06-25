package enrich

import (
	"context"
	"strings"
)

// Common permutation patterns applied to discovered names
var permutationPatterns = []string{
	"dev", "staging", "stage", "prod", "production", "test", "qa", "uat",
	"api", "api2", "v1", "v2", "v3", "internal", "int", "ext", "public",
	"admin", "manage", "portal", "dashboard", "backend", "frontend",
	"app", "apps", "service", "services", "cloud", "cdn", "static",
	"mail", "smtp", "pop", "imap", "vpn", "ssh", "ftp", "sftp",
	"www", "www2", "ww1", "web", "new", "old", "legacy", "beta", "alpha",
	"demo", "sandbox", "lab", "labs", "preview", "canary", "green", "blue",
	"us", "eu", "ap", "us-east", "us-west", "eu-west", "ap-southeast",
	"01", "02", "1", "2", "3", "001",
}

// Permute generates subdomain candidates by applying patterns to a base domain.
// Given "example.com" and found subdomain "api.example.com", it generates:
//   dev-api.example.com, api-dev.example.com, api2.example.com, etc.
func Permute(ctx context.Context, domain string, found []string) <-chan string {
	out := make(chan string, 256)
	go func() {
		defer close(out)
		suffix := "." + domain
		seen := make(map[string]bool)

		emit := func(s string) {
			s = strings.ToLower(s)
			if !seen[s] {
				seen[s] = true
				select {
				case out <- s:
				case <-ctx.Done():
				}
			}
		}

		for _, sub := range found {
			// Strip domain suffix to get the label part
			label := strings.TrimSuffix(sub, suffix)
			if label == sub {
				continue // didn't match
			}

			for _, pat := range permutationPatterns {
				// prefix: pat-label.domain
				emit(pat + "-" + label + suffix)
				// suffix: label-pat.domain
				emit(label + "-" + pat + suffix)
				// combined: pat.label.domain (extra tier)
				emit(pat + "." + label + suffix)
				// numericappend: label1, label2
				emit(label + pat + suffix)
			}

			// Also try common separators with existing label parts
			parts := strings.Split(label, "-")
			if len(parts) > 1 {
				// Rebuild without one part
				for i := range parts {
					reduced := make([]string, 0, len(parts)-1)
					for j, p := range parts {
						if j != i {
							reduced = append(reduced, p)
						}
					}
					emit(strings.Join(reduced, "-") + suffix)
				}
			}
		}
	}()
	return out
}

// Package stack fingerprints the technology stack of a target: frontend
// framework + version, hosting/CDN/deployment platform, cloud provider,
// database hints, and exposed CI/CD config files. Everything here is
// derived from data a normal browser/DNS client would also see — no
// authentication bypass, no exploitation.
package stack

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options configures a stack detection run.
type Options struct {
	URL     string
	Timeout time.Duration
	SkipTLS bool
	// CheckMetadata probes for misconfigured cloud-metadata SSRF exposure
	// (e.g. a reverse proxy that forwards to 169.254.169.254). Off by
	// default — this actively tests for a specific misconfiguration class
	// and should only run against targets you're authorized to test.
	CheckMetadata bool
	Writer        output.Writer
}

type finding struct {
	source     string
	value      string
	version    string
	confidence int
	extra      string
}

// Run performs stack fingerprinting against a single URL.
func Run(ctx context.Context, opts Options) error {
	client := utils.NewClient(utils.ClientConfig{
		Timeout:       opts.Timeout,
		SkipTLSVerify: opts.SkipTLS,
		FollowRedirs:  true,
		MaxRedirects:  5,
	})

	emit := func(f finding) {
		_ = opts.Writer.Write(output.Result{
			Type:       output.TypeStack,
			Source:     f.source,
			Value:      f.value,
			Version:    f.version,
			Confidence: f.confidence,
			Extra:      f.extra,
			Timestamp:  time.Now(),
		})
	}

	base := strings.TrimRight(opts.URL, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	bodyStr := string(body)

	for _, f := range detectFrameworks(resp.Header, bodyStr) {
		emit(f)
	}
	for _, f := range detectHostingPlatform(resp.Header) {
		emit(f)
	}
	for _, f := range detectCloudProvider(resp.Header) {
		emit(f)
	}
	for _, f := range detectDatabaseHints(bodyStr) {
		emit(f)
	}

	// Build-manifest probes refine framework version when a body
	// signature alone can't, and confirm CI/CD config exposure.
	soft := calibrateSoft404(ctx, client, base)
	for _, f := range probeAuxFiles(ctx, client, base, soft) {
		emit(f)
	}

	if opts.CheckMetadata {
		for _, f := range probeMetadataExposure(ctx, client, base, soft) {
			emit(f)
		}
	}

	if resp.TLS != nil {
		for _, f := range detectFromTLS(resp.TLS) {
			emit(f)
		}
	}

	return nil
}

// --- Framework + version detection ---

var nextBuildIDRe = regexp.MustCompile(`/_next/static/([^/"']+)/`)
var nextVersionMetaRe = regexp.MustCompile(`"version":"(\d+\.\d+\.\d+[^"]*)"`)
var nuxtVersionRe = regexp.MustCompile(`__NUXT__.*?version["']?\s*[:=]\s*["'](\d+\.\d+\.\d+)`)
var wpVersionRe = regexp.MustCompile(`content="WordPress\s+([\d.]+)"`)
var generatorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
var laravelDebugRe = regexp.MustCompile(`Laravel\s+(?:Framework\s+)?v?(\d+\.\d+(?:\.\d+)?)`)
var djangoDebugRe = regexp.MustCompile(`Django\s+Version:\s*(\d+\.\d+(?:\.\d+)?)`)

func detectFrameworks(h http.Header, body string) []finding {
	var out []finding

	if h.Get("X-Powered-By") != "" {
		out = append(out, finding{source: "header", value: "X-Powered-By", extra: h.Get("X-Powered-By"), confidence: 90})
	}

	// Next.js: build ID alone doesn't carry a semver, but the presence of
	// react-server-dom/react version strings shipped in the bundle path
	// or RSC payload sometimes does. Report what's verifiable.
	if m := nextBuildIDRe.FindStringSubmatch(body); m != nil {
		out = append(out, finding{source: "framework", value: "Next.js", confidence: 95, extra: "build id " + m[1]})
	} else if strings.Contains(body, "__NEXT_DATA__") || strings.Contains(body, "/_next/") {
		out = append(out, finding{source: "framework", value: "Next.js", confidence: 80})
	}
	if m := nextVersionMetaRe.FindStringSubmatch(body); m != nil {
		out = append(out, finding{source: "framework", value: "Next.js", version: m[1], confidence: 70, extra: "version string found in page payload"})
	}

	if m := nuxtVersionRe.FindStringSubmatch(body); m != nil {
		out = append(out, finding{source: "framework", value: "Nuxt.js", version: m[1], confidence: 85})
	} else if strings.Contains(body, "__NUXT__") {
		out = append(out, finding{source: "framework", value: "Nuxt.js", confidence: 80})
	}

	if m := wpVersionRe.FindStringSubmatch(body); m != nil {
		out = append(out, finding{source: "framework", value: "WordPress", version: m[1], confidence: 95, extra: "meta generator tag"})
	}

	if m := generatorRe.FindStringSubmatch(body); m != nil {
		out = append(out, finding{source: "framework", value: strings.TrimSpace(m[1]), confidence: 90, extra: "meta generator tag"})
	}

	if m := laravelDebugRe.FindStringSubmatch(body); m != nil {
		out = append(out, finding{source: "framework", value: "Laravel", version: m[1], confidence: 95, extra: "leaked in debug/error page — fix: disable APP_DEBUG in production"})
	}
	if m := djangoDebugRe.FindStringSubmatch(body); m != nil {
		out = append(out, finding{source: "framework", value: "Django", version: m[1], confidence: 95, extra: "leaked in DEBUG=True error page"})
	}

	if strings.Contains(body, "data-reactroot") || strings.Contains(body, "react-dom") {
		out = append(out, finding{source: "framework", value: "React", confidence: 60})
	}
	if strings.Contains(body, "ng-version=") {
		if m := regexp.MustCompile(`ng-version="([\d.]+)"`).FindStringSubmatch(body); m != nil {
			out = append(out, finding{source: "framework", value: "Angular", version: m[1], confidence: 95})
		}
	}

	return out
}

// --- Hosting / deployment platform detection (from response headers) ---

func detectHostingPlatform(h http.Header) []finding {
	var out []finding
	checks := []struct {
		header, contains, platform string
	}{
		{"Server", "vercel", "Vercel"},
		{"X-Vercel-Id", "", "Vercel"},
		{"X-Vercel-Cache", "", "Vercel"},
		{"Server", "netlify", "Netlify"},
		{"X-Nf-Request-Id", "", "Netlify"},
		{"Server", "cloudflare", "Cloudflare"},
		{"Cf-Ray", "", "Cloudflare"},
		{"X-Github-Request-Id", "", "GitHub Pages"},
		{"Server", "github.com", "GitHub Pages"},
		{"X-Amz-Cf-Id", "", "AWS CloudFront"},
		{"Via", "cloudfront", "AWS CloudFront"},
		{"X-Amz-Request-Id", "", "AWS (S3/API Gateway)"},
		{"X-Ms-Request-Id", "", "Microsoft Azure"},
		{"X-Azure-Ref", "", "Microsoft Azure"},
		{"Server", "gws", "Google (Frontend)"},
		{"X-Goog-Trace-Id", "", "Google Cloud"},
		{"Via", "google frontend", "Google Cloud"},
		{"X-Render-Origin-Server", "", "Render"},
		{"X-Railway-Request-Id", "", "Railway"},
		{"X-Fly-Request-Id", "", "Fly.io"},
		{"Server", "heroku", "Heroku"},
		{"X-Heroku-Dynos-In-Use", "", "Heroku"},
		{"X-Pantheon-Styx-Hostname", "", "Pantheon"},
		{"X-Served-By", "fastly", "Fastly CDN"},
	}
	for _, c := range checks {
		v := h.Get(c.header)
		if v == "" {
			continue
		}
		if c.contains == "" || strings.Contains(strings.ToLower(v), c.contains) {
			out = append(out, finding{source: "hosting", value: c.platform, confidence: 85, extra: fmt.Sprintf("%s: %s", c.header, v)})
		}
	}
	return out
}

// --- Cloud provider hints (separate from CDN/hosting since a site can
// sit behind Cloudflare yet be hosted on AWS origin, etc.) ---

func detectCloudProvider(h http.Header) []finding {
	var out []finding
	if h.Get("X-Amz-Cf-Id") != "" || h.Get("X-Amz-Request-Id") != "" || h.Get("X-Amzn-Trace-Id") != "" {
		out = append(out, finding{source: "cloud", value: "AWS", confidence: 80})
	}
	if h.Get("X-Ms-Request-Id") != "" || h.Get("X-Azure-Ref") != "" {
		out = append(out, finding{source: "cloud", value: "Microsoft Azure", confidence: 80})
	}
	if h.Get("X-Goog-Trace-Id") != "" || strings.Contains(strings.ToLower(h.Get("Server")), "gws") {
		out = append(out, finding{source: "cloud", value: "Google Cloud", confidence: 75})
	}
	return out
}

// --- Database hints from leaked error strings (extends webtech's
// error-page detection with DB-specific signatures) ---

var dbSignatures = map[string]string{
	"you have an error in your sql syntax": "MySQL",
	"mysqli_":                              "MySQL",
	"warning: pg_":                         "PostgreSQL",
	"postgresql.*error":                    "PostgreSQL",
	"org.postgresql.util.psqlexception":    "PostgreSQL",
	"mongodb.driver":                       "MongoDB",
	"mongoerror":                           "MongoDB",
	"redis::commanderror":                  "Redis",
	"ora-[0-9]{5}":                         "Oracle DB",
	"microsoft sql server":                 "Microsoft SQL Server",
	"unclosed quotation mark after the character string": "Microsoft SQL Server",
	"sqlite3::": "SQLite",
}

func detectDatabaseHints(body string) []finding {
	var out []finding
	lower := strings.ToLower(body)
	for pattern, db := range dbSignatures {
		matched := false
		if strings.Contains(pattern, "[") || strings.Contains(pattern, ".*") {
			if ok, _ := regexp.MatchString(pattern, lower); ok {
				matched = true
			}
		} else if strings.Contains(lower, pattern) {
			matched = true
		}
		if matched {
			out = append(out, finding{source: "database", value: db, confidence: 75, extra: "leaked via error message — fix: disable verbose DB errors in production"})
		}
	}
	return out
}

// --- Auxiliary file probes: build manifests + CI/CD config exposure ---

type auxProbe struct {
	path   string
	label  string
	source string
	parse  func(body string) (version, extra string)
}

// softFingerprint captures the shape of a target's catch-all/SPA response,
// so a 200 returned for a nonexistent random path isn't later mistaken for
// a genuinely exposed file at a well-known path (same technique as
// internal/dirfuzz's soft-404 calibration).
type softFingerprint struct {
	active bool
	size   int64
	body   []byte
}

func calibrateSoft404(ctx context.Context, client *http.Client, base string) softFingerprint {
	randomPath := "/spectre-stack-probe-" + randomHex(8)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+randomPath, nil)
	if err != nil {
		return softFingerprint{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return softFingerprint{}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return softFingerprint{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return softFingerprint{active: true, size: int64(len(body)), body: body}
}

func randomHex(n int) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, n*2)
	for i := range b {
		b[i] = hexDigits[mrand.Intn(len(hexDigits))]
	}
	return string(b)
}

// looksLikeSoftMatch reports whether resp matches the soft-404 fingerprint
// (same byte size, or substantially the same body) — i.e. the server served
// its catch-all page rather than the file at the probed path.
func (sf softFingerprint) looksLikeSoftMatch(size int64, body []byte) bool {
	if !sf.active {
		return false
	}
	if size == sf.size {
		return true
	}
	if len(sf.body) > 0 && len(body) > 0 && bytes.Equal(sf.body, body) {
		return true
	}
	return false
}

func probeAuxFiles(ctx context.Context, client *http.Client, base string, soft softFingerprint) []finding {
	probes := []auxProbe{
		{"/package.json", "package.json exposed", "deployment", parsePackageJSON},
		{"/.git/HEAD", ".git directory exposed", "deployment", nil},
		{"/.github/workflows/ci.yml", "GitHub Actions workflow exposed", "pipeline", nil},
		{"/.gitlab-ci.yml", "GitLab CI config exposed", "pipeline", nil},
		{"/Jenkinsfile", "Jenkins pipeline config exposed", "pipeline", nil},
		{"/.travis.yml", "Travis CI config exposed", "pipeline", nil},
		{"/vercel.json", "Vercel config exposed", "pipeline", nil},
		{"/netlify.toml", "Netlify config exposed", "pipeline", nil},
		{"/.env", ".env file exposed", "deployment", nil},
		{"/docker-compose.yml", "docker-compose.yml exposed", "deployment", nil},
	}

	results := make([]*finding, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p auxProbe) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+p.path, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
			if resp.StatusCode != http.StatusOK || len(body) == 0 {
				return
			}
			if soft.looksLikeSoftMatch(int64(len(body)), body) {
				return // catch-all/SPA response, not a real exposed file
			}
			version, extra := "", "HTTP 200 at "+p.path+" — should return 404 in production"
			if p.parse != nil {
				version, extra = p.parse(string(body))
			}
			results[i] = &finding{source: p.source, value: p.label, version: version, confidence: 95, extra: extra}
		}(i, p)
	}
	wg.Wait()

	var out []finding
	for _, f := range results {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func parsePackageJSON(body string) (version, extra string) {
	var pkg struct {
		Name            string            `json:"name"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(body), &pkg); err != nil {
		return "", "package.json exposed but unparsable"
	}
	if pkg.Name == "" && len(pkg.Dependencies) == 0 && len(pkg.DevDependencies) == 0 {
		return "", "package.json exposed but has no recognizable npm fields — possibly a different JSON file at this path"
	}
	deps := map[string]string{}
	for k, v := range pkg.Dependencies {
		deps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		deps[k] = v
	}
	interesting := []string{"next", "react", "vue", "nuxt", "@angular/core", "express", "fastify", "svelte", "gatsby"}
	var parts []string
	for _, name := range interesting {
		if v, ok := deps[name]; ok {
			parts = append(parts, fmt.Sprintf("%s@%s", name, strings.TrimLeft(v, "^~=>< ")))
		}
	}
	if len(parts) == 0 {
		return "", "package.json exposed (no recognized framework deps)"
	}
	return "", "exact pinned versions from package.json: " + strings.Join(parts, ", ")
}

// --- Optional: misconfigured cloud-metadata SSRF exposure check.
// Only fires if the operator opts in via --check-metadata; tests for a
// reverse proxy or app endpoint that forwards arbitrary paths/hosts to a
// cloud instance-metadata service (AWS, GCP, Azure, DigitalOcean all use
// 169.254.169.254; GCP also answers on metadata.google.internal).

// metadataSignature requires at least two of these markers together, since
// any single one of them ("hostname", "id") is common enough in ordinary
// page content to false-positive on its own.
var metadataSignatures = []string{"ami-id", "instance-id", "iam/security-credentials", "computeMetadata", "instance/zone", "Metadata-Flavor"}

func probeMetadataExposure(ctx context.Context, client *http.Client, base string, soft softFingerprint) []finding {
	var out []finding
	candidates := []string{
		"/latest/meta-data/",
		"/latest/meta-data/iam/security-credentials/",
		"/computeMetadata/v1/",
		"/metadata/instance?api-version=2021-02-01",
		"/?url=http://169.254.169.254/latest/meta-data/",
		"/proxy?url=http://169.254.169.254/latest/meta-data/",
		"/?url=http://metadata.google.internal/computeMetadata/v1/",
	}
	for _, path := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Metadata-Flavor", "Google")
		req.Header.Set("Metadata", "true")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || soft.looksLikeSoftMatch(int64(len(body)), body) {
			continue
		}
		hits := 0
		for _, sig := range metadataSignatures {
			if strings.Contains(string(body), sig) {
				hits++
			}
		}
		if hits >= 2 {
			out = append(out, finding{
				source:     "vulnerability",
				value:      "Cloud metadata SSRF exposure",
				confidence: 90,
				extra:      fmt.Sprintf("path %s returned instance-metadata-like content — possible SSRF to cloud metadata service", path),
			})
		}
	}
	return out
}

func detectFromTLS(state *tls.ConnectionState) []finding {
	var out []finding
	for _, cert := range state.PeerCertificates {
		issuer := cert.Issuer.CommonName
		switch {
		case strings.Contains(issuer, "Amazon"):
			out = append(out, finding{source: "cloud", value: "AWS Certificate Manager", confidence: 70, extra: "TLS issuer: " + issuer})
		case strings.Contains(issuer, "Google Trust Services") || strings.Contains(issuer, "GTS"):
			out = append(out, finding{source: "cloud", value: "Google Cloud (cert)", confidence: 60, extra: "TLS issuer: " + issuer})
		case strings.Contains(issuer, "Cloudflare"):
			out = append(out, finding{source: "hosting", value: "Cloudflare", confidence: 70, extra: "TLS issuer: " + issuer})
		case strings.Contains(issuer, "Let's Encrypt"):
			out = append(out, finding{source: "tls", value: "Let's Encrypt", confidence: 60, extra: "TLS issuer: " + issuer})
		}
		break // only the leaf cert matters here
	}
	return out
}

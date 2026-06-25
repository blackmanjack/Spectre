package webtech

import (
	"context"
	"crypto/md5" //nolint:gosec — mmh3/md5 used only for favicon fingerprint, not security
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/utils"
)

// Options for web technology fingerprinting.
type Options struct {
	URL     string
	Timeout time.Duration
	SkipTLS bool
	Writer  output.Writer
}

// Run performs HTTP fingerprinting: headers, cookies, meta tags, favicon, TLS.
func Run(ctx context.Context, opts Options) error {
	client := utils.NewClient(utils.ClientConfig{
		Timeout:       opts.Timeout,
		SkipTLSVerify: opts.SkipTLS,
		FollowRedirs:  true,
		MaxRedirects:  5,
	})

	emit := func(tech, detail string) {
		_ = opts.Writer.Write(output.Result{
			Type:      output.TypeWebTech,
			Value:     tech,
			Extra:     detail,
			Timestamp: time.Now(),
		})
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB
	bodyStr := strings.ToLower(string(body))

	// --- Response headers ---
	fingerprint := func(header, tech string) {
		if val := resp.Header.Get(header); val != "" {
			emit(tech, fmt.Sprintf("%s: %s", header, val))
		}
	}
	fingerprint("Server", "Web Server")
	fingerprint("X-Powered-By", "Backend Technology")
	fingerprint("X-Generator", "CMS/Generator")
	fingerprint("X-Drupal-Cache", "Drupal")
	fingerprint("X-Wp-Total-Pages", "WordPress")

	// --- Security header audit ---
	secHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"Content-Security-Policy":   "CSP",
		"X-Frame-Options":           "Clickjacking Protection",
		"X-Content-Type-Options":    "MIME Sniffing Protection",
		"Referrer-Policy":           "Referrer Policy",
		"Permissions-Policy":        "Permissions Policy",
	}
	for header, desc := range secHeaders {
		if resp.Header.Get(header) == "" {
			emit("MISSING: "+desc, fmt.Sprintf("header %s not set", header))
		}
	}

	// --- Cookie flags ---
	for _, cookie := range resp.Cookies() {
		issues := []string{}
		if !cookie.HttpOnly {
			issues = append(issues, "missing HttpOnly")
		}
		if !cookie.Secure {
			issues = append(issues, "missing Secure")
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			issues = append(issues, "SameSite not set")
		}
		if len(issues) > 0 {
			emit("Cookie Issue", fmt.Sprintf("%s: %s", cookie.Name, strings.Join(issues, ", ")))
		}
	}

	// --- HTML body signatures ---
	sigMap := map[string]string{
		"wp-content":              "WordPress",
		"wp-includes":             "WordPress",
		"joomla":                  "Joomla",
		"drupal":                  "Drupal",
		"laravel":                 "Laravel",
		"django":                  "Django",
		"rails":                   "Ruby on Rails",
		"react":                   "React",
		"vue":                     "Vue.js",
		"angular":                 "Angular",
		"jquery":                  "jQuery",
		"bootstrap":               "Bootstrap",
		"next.js":                 "Next.js",
		"__next":                  "Next.js",
		"nuxt":                    "Nuxt.js",
		"gatsby":                  "Gatsby",
		"shopify":                 "Shopify",
		"magento":                 "Magento",
		"woocommerce":             "WooCommerce",
		"cloudflare":              "Cloudflare",
		"google-analytics":        "Google Analytics",
		"gtag":                    "Google Tag Manager",
		"intercom":                "Intercom",
		"hubspot":                 "HubSpot",
		"nginx":                   "Nginx",
		"apache":                  "Apache",
		"phpinfo()":               "PHP Info Exposed",
		"error_reporting":         "PHP Errors Visible",
		"traceback":               "Python Traceback Exposed",
		"application error":       "App Error Exposed",
	}
	found := make(map[string]bool)
	for sig, tech := range sigMap {
		if strings.Contains(bodyStr, sig) && !found[tech] {
			found[tech] = true
			emit(tech, "detected via body signature")
		}
	}

	// --- Favicon hash fingerprint ---
	favURL := strings.TrimRight(opts.URL, "/") + "/favicon.ico"
	favReq, err := http.NewRequestWithContext(ctx, http.MethodGet, favURL, nil)
	if err == nil {
		if favResp, err := client.Do(favReq); err == nil {
			defer favResp.Body.Close()
			favData, _ := io.ReadAll(io.LimitReader(favResp.Body, 32*1024))
			if len(favData) > 0 {
				h := md5.Sum(favData) //nolint:gosec
				emit("Favicon MD5", hex.EncodeToString(h[:]))
			}
		}
	}

	// --- TLS info ---
	if resp.TLS != nil {
		for _, cert := range resp.TLS.PeerCertificates {
			emit("TLS Certificate", fmt.Sprintf("CN=%s, SANs=%s, Expires=%s",
				cert.Subject.CommonName,
				strings.Join(cert.DNSNames, ","),
				cert.NotAfter.Format("2006-01-02"),
			))
		}
	}

	return nil
}

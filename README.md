# SPECTRE

**S**can · **P**robe · **E**numerate · **C**rawl · **T**race · **R**econ · **E**xamine

A fast, single-binary reconnaissance suite written in Go, for **authorized security
testing only** (pentest engagements, bug bounty programs you're enrolled in, CTFs,
or infrastructure you own). It combines subdomain enumeration, directory fuzzing,
port scanning, DNS recon, web technology fingerprinting, and full technology-stack
detection (framework/version, hosting/CDN, cloud provider, DB hints, exposed
CI/CD config) in one tool.

This README documents what the tool actually does today, including parts that
are still stubs — see [Known limitations](#known-limitations--honest-status) before
relying on a feature.

---

## Install / Build

Requires Go 1.22+.

```bash
git clone <this-repo>
cd Recon
go mod tidy
go build -ldflags="-s -w" -o spectre .      # Linux/macOS
go build -ldflags="-s -w" -o spectre.exe .  # Windows
```

Cross-compile:
```bash
GOOS=linux   GOARCH=amd64 go build -o spectre-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o spectre-windows-amd64.exe .
GOOS=darwin  GOARCH=arm64 go build -o spectre-darwin-arm64 .
```

See [BUILD.md](BUILD.md) for verification/benchmark commands.

---

## Global flags (apply to every subcommand)

| Flag | Default | Meaning |
|---|---|---|
| `-o, --output <file>` | stdout | Write results to a file instead of stdout |
| `-f, --format text\|json` | `text` | Output format. `json` is NDJSON (one JSON object per line) |
| `--scope <file>` | none | Authorize targets via an allowlist file. **If omitted, no scope check runs** — you are responsible for authorization |
| `--no-audit` | audit on | Disable the append-only audit log at `~/.spectre/audit.jsonl` |
| `-s, --silent` | off | Suppress the banner and progress messages on stderr |
| `--no-color` | off | Disable ANSI colors in text output |

### Scope files

One entry per line — CIDR, exact host/domain, or `*.wildcard`:
```
example.com
*.example.com
10.0.0.0/24
192.168.1.50
```
Any target not matching an entry is refused before any packet is sent, and the
process exits non-zero. Comments (`#`) and blank lines are ignored.

### Audit log

Every run appends one JSON line to `~/.spectre/audit.jsonl`:
```json
{"timestamp":"2026-06-26T00:20:17Z","command":"dns","target":"example.com","operator":"yourname","pid":29096}
```
Use this to keep a record of what you scanned and when for an engagement.

---

## `spectre subdomain` — subdomain enumeration

```
spectre subdomain -d <domain> [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `-d, --domain` | — | **Required.** Target domain |
| `-p, --passive` | off | Passive sources only, no DNS brute force |
| `-b, --brute` | off | Brute force only, skip passive sources |
| `--fast` | off | Passive-only, streaming, **no DNS resolve** — raw names printed as found, for head-to-head speed comparison against tools like `assetfinder` |
| `--all` | off | Runs passive+brute, then the coverage maximizers: permutation, bounded recursive permutation, Wayback/CommonCrawl archive mining, GitHub code search, and search-engine dorking. Every candidate is resolved and deduplicated before being reported |
| `-w, --wordlist` | embedded `subdomains.txt` | Wordlist path, or a catalog name/group (e.g. `subdomain:medium`) — see [Wordlists](#spectre-wordlists--wordlist-catalog-manager) |
| `-c, --concurrency` | 50 | Concurrent DNS brute-force workers |
| `-t, --timeout` | 10 | Per-request timeout (seconds) |
| `-r, --rate` | 100 | Requests/second |
| `--resolvers` | `8.8.8.8:53,1.1.1.1:53,9.9.9.9:53` | DNS resolvers to use (comma-separated `ip:port`) |
| `--sources` | all | Comma-separated passive sources: `crtsh,hackertarget,alienvault,rapiddns,certspotter` |
| `--skip-wildcard` | off | Skip wildcard-DNS detection before brute forcing |
| `--proxies <file>` | none | Route passive-source HTTP requests through a proxy list (one `http://` or `socks5://` URL per line) for anti-block rotation |
| `--github-token <token>` | none | Used by `--all`'s GitHub code-search enricher. Optional — GitHub search works unauthenticated at a much lower rate limit (60 req/hour) without it |

**Passive sources queried:** crt.sh, HackerTarget, AlienVault OTX, RapidDNS, CertSpotter.
Each runs concurrently; a slow or failing source doesn't block the others.

**Coverage maximizers (`--all`):** on top of passive+brute, permutes discovered
names against ~50 common patterns (`dev-`, `-staging`, `api2`, etc.), recursively
permutes newly-confirmed names up to depth 2, mines Wayback Machine + CommonCrawl
for historical URLs under the domain, searches GitHub code for mentions, and
dorks a search engine with `site:domain -www`. Every candidate is resolved
before being reported — unresolvable names are discarded, not printed.

**Wildcard detection:** before brute forcing, three random subdomain labels are
resolved. If all three resolve to the same IP set, that domain has wildcard DNS —
SPECTRE records those IPs and silently discards brute-force hits that only match
the wildcard, so you don't get thousands of false positives.

**Examples:**
```bash
spectre subdomain -d example.com --passive -f json -o subs.json
spectre subdomain -d example.com --brute -c 100 -w subdomain:medium
spectre subdomain -d example.com --fast              # fast, unresolved, streaming
spectre subdomain -d example.com --proxies proxies.txt
```

---

## `spectre dirfuzz` — directory & file fuzzing

```
spectre dirfuzz -u <url> [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `-u, --url` | — | **Required.** Target base URL |
| `-w, --wordlist` | embedded `directories.txt` | Wordlist path or catalog group (e.g. `directory:medium`) |
| `-x, --extensions` | none | Comma-separated extensions to append per word: `php,html,txt` |
| `-m, --method` | `GET` | HTTP method |
| `-c, --concurrency` | 50 | Concurrent workers |
| `-t, --timeout` | 10 | Per-request timeout (seconds) |
| `-r, --rate` | 150 | Requests/second |
| `--status-filter` | `200,204,301,302,307,401,403` | Only show these status codes |
| `--status-exclude` | none | Exclude these status codes (ignored if `--status-filter` is set) |
| `--size-exclude` | none | Exclude responses of these exact byte sizes |
| `--body-exclude` | none | Exclude responses whose body contains this string |
| `--skip-tls` | off | Skip TLS certificate verification |
| `--follow-redir` | off | Follow HTTP redirects |
| `--headers` | none | Extra headers: `Key:Value,Key2:Value2` |
| `--cookies` | none | Cookie header value |
| `--waf-evasion` | off | Add IP-spoofing/host-override headers (`X-Forwarded-For`, `X-Original-URL`, etc.) to each request |
| `--recursive` | off | Re-fuzz any discovered directory (status 200/301/302/403, no `.` in path) |
| `--depth` | 3 | Maximum recursion depth |
| `--proxies <file>` | none | Route requests through a proxy list (one `http://` or `socks5://` URL per line) for anti-block rotation |

**Soft-404 auto-calibration:** before fuzzing, a random nonsense path is requested.
If the server returns a non-404 (common with SPA/catch-all routing), that response's
body and size become a fingerprint and matching results are automatically excluded.

**Recursive descent:** the wordlist is loaded into memory once and reused at every
recursion depth — it isn't re-read from disk per directory. Directory names that
contain `..`, `?`, or `#` are rejected before being folded into a recursive URL.

**Examples:**
```bash
spectre dirfuzz -u https://example.com -x php,html,txt
spectre dirfuzz -u https://example.com -w directory:large --recursive --depth 2
spectre dirfuzz -u https://example.com --waf-evasion --status-exclude 404
```

---

## `spectre portscan` — port scanner

```
spectre portscan -t <target> [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `-t, --target` | — | **Required.** IP, hostname, or CIDR |
| `-p, --ports` | top 1000 | Port spec: `80,443`, `1-1000`, or `-` for all 65535 |
| `--all-ports` | off | Scan all 65535 ports |
| `--top-ports <N>` | 1000 | Scan the top N most common ports |
| `-c, --concurrency` | 5000 | Discovery-phase goroutines |
| `--timeout` | 800 | Per-port timeout (**milliseconds**) |
| `-r, --rate` | 0 | Packets/sec. `0` means "use `--timing` template instead" |
| `--scan-type` | `connect` | `connect`, or `syn`/`fin`/`null`/`xmas`/`ack` — see note below |
| `--udp` | off | Also scan UDP ports — see note below |
| `--service` | off | Enable banner-grab + service fingerprinting on confirmed-open ports |
| `--os` | off | Enable OS detection (TTL-based; **Unix only**, see below) |
| `--retry` | 2 | Retries per port during Phase 2 confirmation |
| `--adaptive` | on | Adaptive rate backoff on timeouts/ICMP storms |
| `--timing` | `T4` | `T0`–`T5` (paranoid→insane) or named: `paranoid,sneaky,polite,normal,aggressive,insane` — see note below |
| `--decoys` | — | Spoofed source IPs to interleave with the real probe, e.g. `"10.0.0.1,10.0.0.2,ME"` (`ME` = real outbound IP). Requires a raw `--scan-type` — see below |
| `--fragment` | off | Split the crafted TCP header across two IP fragments to defeat stateless IDS/IPS signature matching. Requires a raw `--scan-type` |
| `--mtu` | 8 | Bytes of TCP header in the first IP fragment when `--fragment` is set (must be a multiple of 8; minimum 8) |

**Scan pipeline (what actually runs today):**
1. **Discovery** — fast concurrent TCP-connect sweep across the requested ports,
   shuffled and (on stealth timing tiers) jittered per the `--timing` template
2. **Confirmation** — re-verifies each candidate. With `--scan-type connect`
   (the default), this is TCP-connect + retries. With `syn`/`fin`/`null`/`xmas`/`ack`
   *and* root/CAP_NET_RAW on Unix, this sends the real crafted probe via a raw
   socket and classifies the response per RFC 793 — see below
3. **UDP scan** (`--udp`) — sends a protocol-specific probe (DNS/NTP/SNMP) or a
   generic datagram per port; `open` on a real response, `closed` only if an
   ICMP port-unreachable is positively correlated (root/admin + Unix), otherwise
   honestly reported as `open|filtered`
4. **Service detection** (`--service`) — grabs a banner and matches it against an
   embedded probe database (`wordlists/service-probes.txt`, derived from
   `nmap-service-probes` format)
5. **OS detection** (`--os`) — reads the live `IP_TTL` socket option from the first
   open connection (Unix only) and matches it against an embedded fingerprint
   database. **On Windows, or if the measurement fails, this reports
   "unavailable" rather than guessing.**

**`--scan-type` on Unix with root/CAP_NET_RAW:** `syn` sends a SYN and classifies
SYN-ACK as open, RST as closed, silence as filtered. `ack` sends a bare ACK to
distinguish stateful firewalls (silence) from stateless ones (RST = unfiltered).
`fin`/`null`/`xmas` rely on RFC 793: a compliant open port stays silent, a closed
one sends RST. **On Windows, these always fall back to `connect`, including
under Administrator** — Windows has forbidden sending TCP data over raw sockets
since Vista, which is an OS-level restriction with no privilege level that lifts
it. SPECTRE detects the failure and warns rather than silently mislabeling
connect-scan results as SYN-scan results.

**`--timing`:** every tier sets the requests/second rate. The stealth tiers
(`T0`–`T2` / `paranoid`/`sneaky`/`polite`) additionally shuffle the port probe
order and add a randomized jitter delay before each probe, so there's no fixed
sequential-sweep or fixed-interval signature.

**`--decoys` and `--fragment` (Unix, raw `--scan-type` only):** both require a
raw IP socket — they only take effect with `--scan-type syn/fin/null/xmas/ack`
and root/`CAP_NET_RAW`. With `--scan-type connect` (the default), or without
raw-socket privilege, SPECTRE prints an explicit `[warn]` and skips them rather
than silently ignoring the flag.
- `--decoys "ip1,ip2,ME"` fires a spoofed-source-IP copy of the probe from each
  listed IP (shuffled order, fire-and-forget, source IP set via a second raw
  socket bound to protocol 255 since the kernel overwrites the source address
  on normal `IPPROTO_TCP` raw sends). `ME` substitutes the scanner's real
  outbound IP so it isn't trivially the odd one out.
- `--fragment` splits the crafted TCP header into two IP fragments (offsets
  aligned to RFC 791's 8-byte unit) so a stateless IDS/IPS that only inspects
  the first fragment never sees the TCP flags byte. `--mtu` controls the split
  point; if too small or too large to leave both fragments non-empty,
  SPECTRE falls back to an unfragmented probe.

**Privilege requirements:** `connect`-type confirmation (the default) and
`--service`/`--os` work without elevation on any OS. `--scan-type syn/fin/null/xmas/ack`
(and therefore `--decoys`/`--fragment`) need root or `CAP_NET_RAW` on Unix (not
available at all on Windows). `--udp` works unprivileged everywhere, but its
`closed` classification (vs. the more honest `open|filtered`) needs root/admin
on Unix for the ICMP listener.

**Examples:**
```bash
spectre portscan -t 192.168.1.1 --all-ports
spectre portscan -t example.com -p 80,443,22,8080 --service
spectre portscan -t 10.0.0.0/24 --top-ports 1000 --os -f json -o scan.json
spectre portscan -t 8.8.8.8 -p 53,123 --udp                    # UDP probes
sudo spectre portscan -t 10.0.0.5 -p 1-1000 --scan-type syn     # real SYN scan (Unix)
spectre portscan -t 10.0.0.5 -p 1-1000 --timing polite          # jittered + shuffled
sudo spectre portscan -t 10.0.0.5 --scan-type syn --decoys "10.0.0.9,ME" --fragment
```

---

## `spectre dns` — DNS reconnaissance

```
spectre dns <domain> [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `--resolvers` | `8.8.8.8:53,1.1.1.1:53` | DNS resolvers (`ip:port`) |
| `--timeout` | 10 | Query timeout (seconds) |
| `--axfr` | on | Attempt a DNS zone transfer (AXFR) against each discovered nameserver |

Resolves A/AAAA, MX, NS, TXT records; does reverse-DNS (PTR) lookups for every
resolved A record; probes a small set of common subdomains (`www`, `mail`, `smtp`,
`ftp`, `vpn`, `api`); and attempts a zone transfer against each NS — almost always
refused on a properly configured server, but worth checking, and the tool tells
you explicitly if one succeeds (a real finding worth reporting).

**Example:**
```bash
spectre dns example.com
spectre dns example.com --axfr=false -f json -o dns.json
```

---

## `spectre webtech` — web technology fingerprinting

```
spectre webtech <url> [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `--timeout` | 10 | Request timeout (seconds) |
| `--skip-tls` | off | Skip TLS certificate verification |

Reports, in one pass:
- `Server` / `X-Powered-By` / generator headers
- Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy)
- Cookie flag issues (missing `HttpOnly`/`Secure`/`SameSite`)
- Body-signature matches for ~30 common frameworks/CMSes (WordPress, Laravel,
  React, Next.js, Shopify, etc.) and exposed-error indicators (`phpinfo()`,
  Python tracebacks)
- Favicon MD5 hash (useful for matching against known favicon-hash databases)
- The full TLS certificate chain (CN, SANs, expiry)

**Example:**
```bash
spectre webtech https://example.com
```

---

## `spectre stack` — technology stack detection

```
spectre stack <url> [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `--timeout` | 10 | Request timeout (seconds) |
| `--skip-tls` | off | Skip TLS certificate verification |
| `--check-metadata` | off | Also probe for misconfigured cloud-metadata SSRF exposure (active test against a specific misconfiguration class — authorized targets only) |

Goes beyond `webtech`'s header/body fingerprinting to identify the deployed
stack as concretely as a blackbox client can see it:

- **Framework + version** — Next.js (build ID, `__NEXT_DATA__`), Nuxt.js,
  WordPress (meta generator tag), Angular (`ng-version`), and any framework
  whose exact version leaks through a debug/error page (Laravel, Django).
  Where only the framework's presence (not version) is verifiable from the
  page itself, version is left blank rather than guessed.
- **Hosting / CDN / deployment platform** — Vercel, Netlify, Cloudflare,
  AWS CloudFront, GitHub Pages, Render, Railway, Fly.io, Heroku, Pantheon,
  Fastly — all from response headers a normal client receives.
- **Cloud provider hints** — AWS / Azure / Google Cloud, from response
  headers and, separately, from the TLS certificate issuer.
- **Database hints** — MySQL/PostgreSQL/MongoDB/Redis/Oracle/MSSQL/SQLite
  signatures in leaked error output (same honesty rule as `webtech`: only
  reported if the page actually exposed it).
- **Exposed CI/CD and deployment config** — probes for `.git/HEAD`,
  `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.travis.yml`,
  `vercel.json`, `netlify.toml`, `.env`, `docker-compose.yml`, and
  `package.json` (parsed for exact pinned versions of `next`, `react`,
  `vue`, `nuxt`, `@angular/core`, `express`, etc. when present). Each is a
  single GET to a well-known path — finding one is a misconfiguration
  worth reporting, not an exploit.

**`--check-metadata`:** sends a handful of requests that would only return
instance-metadata-shaped content if the target has a reverse proxy or
endpoint that forwards attacker-controlled URLs/hosts to a cloud metadata
service — AWS/DigitalOcean/Azure-style `169.254.169.254` and GCP's
`metadata.google.internal`/`computeMetadata`. A hit requires at least two
metadata-specific markers (`ami-id`, `iam/security-credentials`,
`computeMetadata`, `Metadata-Flavor`, etc.) together, not just one common
word, to avoid false positives. This is an active probe for one specific
SSRF misconfiguration class, not exploitation — off by default, and only
meant for targets you're authorized to test.

**Soft-404 calibration:** before probing `.env`, `.git/HEAD`,
`vercel.json`, and the other well-known paths, a random nonexistent path is
requested first. If the server returns a non-404 (common on SPA/catch-all
routing — most Next.js/Vue/React sites), that response's body and size
become a fingerprint, and any aux-file probe that matches it is discarded
as the catch-all page rather than reported as a real exposure. The same
fingerprint also guards the `--check-metadata` probes.

**Honesty notes:** every finding here is something a normal HTTP/TLS client
also sees — no auth bypass, no credential use, no exploitation. Versions are
only reported when the page itself discloses them (build manifests, debug
output, or an exposed `package.json`); SPECTRE does not guess a version from
a framework's mere presence. Aux-file/CI-CD probes run concurrently and are
guarded by soft-404 calibration so an SPA's catch-all page can't be mistaken
for an exposed config file.

**Example:**
```bash
spectre stack https://example.com
spectre stack https://example.com --check-metadata -f json -o stack.json
```

---

## `spectre breach` — breach/leak exposure check

```
spectre breach <domain-or-email> [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `--timeout` | 15 | Request timeout (seconds) |
| `--rate` | 2 | Requests per second against provider APIs |
| `--skip-paste` | off | Skip the free Pastebin scraper |
| `--hibp-key` | — | HaveIBeenPwned API key ([haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key), paid) |
| `--dehashed-email` | — | DeHashed account email |
| `--dehashed-key` | — | DeHashed API key |

This is **clear-web breach/leak checking**, not dark-web (Tor/.onion) access —
SPECTRE doesn't crawl `.onion` sites, and that's a deliberate scope decision,
not a missing feature: Tor access is a different protocol/threat model from
HTTP recon, and the legally useful signal (has this domain/email leaked
anywhere) lives entirely on the clear web in breach databases and paste sites.

Three sources, each independently skippable/gated and never silently treated
as "clean" if it can't run:

- **Pastebin scraping** (free, no key) — polls Pastebin's public recent-paste
  feed for mentions of your query. Only sees the last ~30 minutes of public
  pastes (no historical search on the free tier), and the scrape endpoint is
  IP-whitelisted by Pastebin — unwhitelisted IPs get HTTP 403, which surfaces
  as an honest "skipped" line, not a fake "no leaks found."
- **HaveIBeenPwned** (bring your own API key via `--hibp-key`) — email-only;
  HIBP's public API has no domain-breach lookup.
- **DeHashed** (bring your own account via `--dehashed-email`/`--dehashed-key`)
  — supports both domain and email queries.

SPECTRE ships no hardcoded paid-API credentials and contacts no breach
database unless you provide your own key — this is a generic framework you
point at the providers you already pay for, not a bundled service.

**Example:**
```bash
spectre breach example.com
spectre breach user@example.com --hibp-key $HIBP_KEY --dehashed-email me@x.com --dehashed-key $DEHASHED_KEY
```

---

## `spectre wordlists` — wordlist catalog manager

SPECTRE does **not** bundle third-party wordlists (SecLists, OneListForAll,
Assetnote, n0kovo, Jhaddix, dirsearch) — only a small wordlist of its own is
embedded in the binary so it works offline by default. Everything else is
fetched **on demand directly from its upstream source**, the same way a package
manager works: SPECTRE hosts nothing, so each list's original license stays
exactly where it is.

```
spectre wordlists list                  # show the full catalog + pulled status
spectre wordlists groups                # show resolvable tag groups
spectre wordlists pull <name>           # download one named list
spectre wordlists pull <category>:<size>  # download every list matching a group, e.g. subdomain:medium
spectre wordlists pull all              # download everything in the catalog
spectre wordlists update                # re-download every list already pulled
spectre wordlists path <name>           # print the local file path of a pulled list
```

Pulled lists are stored at `~/.spectre/wordlists/<name>.txt`. The license of each
list is printed at pull time — review it before using a list against a target.

**Using a wordlist or group with subdomain/dirfuzz:**
```bash
spectre wordlists pull subdomain:medium
spectre subdomain -d example.com -b -w subdomain:medium

spectre wordlists pull directory:large
spectre dirfuzz -u https://example.com -w directory:large
```
A group spec (`category:size`) merges and deduplicates every matching pulled
list across all sources automatically. You can also list multiple names
explicitly: `-w raft-medium-dirs,orwa-short`.

---

## `spectre plugin` — plugin system

```
spectre plugin list             # show registered plugins
spectre plugin run <name> <target>
```

The plugin registry (`internal/plugin`) exists so additional recon modules can be
added without touching the core, but **no plugins ship built-in today** — `spectre
plugin list` will currently print nothing. This is scaffolding for future
extension, not a working feature yet.

---

## Known limitations — honest status

Every feature below is implemented and working. This table exists because
"works" can still mean "works within a platform or protocol constraint" —
SPECTRE documents those constraints explicitly instead of staying silent
about them. Re-verified against the current code as of this writing; if any
row stops matching reality, treat that as a bug report against the README.

**`stack`**
| Feature | Status |
|---|---|
| Framework/version detection | Versions are only reported when a page genuinely discloses them (Next.js build ID, WordPress/Angular meta tags, Laravel/Django debug pages, or an exposed `package.json`). A framework's mere presence (e.g. generic React markup) is reported without a guessed version. |
| Aux-file/CI-CD exposure probes | Guarded by soft-404 calibration (same technique as `dirfuzz`): a random nonexistent path is probed first, and any `.env`/`.git`/`vercel.json`-style hit that matches that catch-all fingerprint is discarded rather than reported as a real exposure. Runs all probes concurrently. |
| `--check-metadata` | Covers AWS/DigitalOcean/Azure-style `169.254.169.254` and GCP's `metadata.google.internal`/`computeMetadata`. Requires 2+ metadata-specific markers in the response (not a single common word) before reporting, and is also guarded by the soft-404 fingerprint. |

**`subdomain` / `dirfuzz`**
| Feature | Status |
|---|---|
| `subdomain --all` | Runs passive+brute, then `internal/enrich`'s coverage maximizers (permutation, bounded recursive permutation, Wayback + CommonCrawl archive mining, GitHub code search, search-engine dorking) on top, resolving and deduplicating every candidate before reporting it. |
| `dirfuzz --proxies` | Routes the dirfuzz HTTP client through the given proxy file (HTTP/SOCKS5), same as `subdomain --proxies`. |
| `dirfuzz --waf-evasion` | Expands each path into `internal/evasion`'s encoding/case/separator mutations and adds its 15-header WAF-bypass set — implemented and wired into the request loop, not cosmetic. |

**`portscan`**
| Feature | Status |
|---|---|
| `--timing` (T0–T5) | Controls rate on every tier. Stealth tiers (T0–T2 / paranoid/sneaky/polite) additionally shuffle probe order and add a randomized per-probe jitter delay (`internal/evasion`), so there's no fixed sequential-sweep or fixed-interval signature. |
| `--decoys` | **Unix with root/CAP_NET_RAW only** (requires a raw `--scan-type`). Fires a shuffled, fire-and-forget spoofed-source-IP copy of each probe via a second raw socket bound to protocol 255 (needed because the kernel overwrites the source address on a normal `IPPROTO_TCP` raw send). Without raw-socket privilege, prints an explicit warning and skips decoys rather than silently dropping the flag. |
| `--fragment` | **Unix with root/CAP_NET_RAW only** (requires a raw `--scan-type`). Splits the crafted TCP header into two IP fragments aligned to RFC 791's 8-byte offset unit, via `--mtu`. Falls back to an unfragmented probe if the requested MTU would leave either fragment empty. |
| `--udp` | Sends protocol-specific probes (DNS, NTP, SNMP) or a generic datagram, classifying `open` on a real response. With root/admin on Unix, also opens a raw ICMP listener to positively confirm `closed`; without that (the common case, and always on Windows) silence is honestly reported as `open\|filtered`, matching Nmap's own documented behavior for the same constraint. |
| `--scan-type syn/fin/null/xmas/ack` | **Works on Unix with root/CAP_NET_RAW.** Sends the real crafted probe via a raw IP socket and classifies per RFC 793. **Does not work on Windows, including under Administrator** — Windows has forbidden sending TCP data over raw sockets since Vista, so `net.ListenIP("ip4:tcp", ...)` always fails there; SPECTRE detects this and falls back to `connect` with an explicit warning rather than silently mislabeling results. |
| `--os` | Real on Unix (reads the live `IP_TTL` socket option and matches an embedded fingerprint table). On Windows, or whenever the measurement fails, it reports "unavailable" rather than fabricating a guess. |

**`breach`**
| Feature | Status |
|---|---|
| Paste-sites | Pastebin's free scrape endpoint only covers the last ~30 minutes of public pastes and is IP-whitelisted (unwhitelisted IPs see HTTP 403, reported as a skip, not a false "clean" result). |
| HIBP / DeHashed | Bring your own API key/account — see `spectre breach`. No keys are bundled; without one, that provider is explicitly skipped rather than silently omitted. |
| Dark-web (Tor/`.onion`) | **Not implemented, by design.** `spectre breach` covers clear-web breach/leak exposure, which is where the legally and practically useful signal lives. `.onion` crawling is a different protocol/threat model and is out of scope. |

**The only hard, unfixable-in-code gap:** raw-socket scan types (and
therefore `--decoys`/`--fragment`) on **Windows**, including under
Administrator. Windows has forbidden sending TCP data over raw sockets
since Vista — an OS-level restriction with no privilege level that lifts
it. A packet-injection driver (Npcap) is the only way around it, and isn't
wired up. If something else here doesn't cover your use case, say so.

---

## Authorized use only

SPECTRE performs active probing (port scans, DNS brute force, directory fuzzing)
against the targets you point it at. Only run it against:
- Systems you own
- Engagements with explicit written authorization (pentest, bug bounty in scope)
- CTF/lab environments designed for this purpose

Use `--scope` to enforce an allowlist and the audit log (`~/.spectre/audit.jsonl`,
on by default) to keep a record of what was run and when.

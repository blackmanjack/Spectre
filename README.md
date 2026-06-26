# SPECTRE

**S**can · **P**robe · **E**numerate · **C**rawl · **T**race · **R**econ · **E**xamine

A fast, single-binary reconnaissance suite written in Go, for **authorized security
testing only** (pentest engagements, bug bounty programs you're enrolled in, CTFs,
or infrastructure you own). It combines subdomain enumeration, directory fuzzing,
port scanning, DNS recon, and web technology fingerprinting in one tool.

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
| `--all` | off | Accepted by the flag parser. **Currently behaves identically to running with neither `--passive` nor `--brute`** (passive + brute together) — see [Known limitations](#known-limitations--honest-status) |
| `-w, --wordlist` | embedded `subdomains.txt` | Wordlist path, or a catalog name/group (e.g. `subdomain:medium`) — see [Wordlists](#spectre-wordlists--wordlist-catalog-manager) |
| `-c, --concurrency` | 50 | Concurrent DNS brute-force workers |
| `-t, --timeout` | 10 | Per-request timeout (seconds) |
| `-r, --rate` | 100 | Requests/second |
| `--resolvers` | `8.8.8.8:53,1.1.1.1:53,9.9.9.9:53` | DNS resolvers to use (comma-separated `ip:port`) |
| `--sources` | all | Comma-separated passive sources: `crtsh,hackertarget,alienvault,rapiddns,certspotter` |
| `--skip-wildcard` | off | Skip wildcard-DNS detection before brute forcing |
| `--proxies <file>` | none | Route passive-source HTTP requests through a proxy list (one `http://` or `socks5://` URL per line) for anti-block rotation |

**Passive sources queried:** crt.sh, HackerTarget, AlienVault OTX, RapidDNS, CertSpotter.
Each runs concurrently; a slow or failing source doesn't block the others.

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
| `--proxies <file>` | none | Accepted but **not yet wired up** — see [Known limitations](#known-limitations--honest-status) |

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
| `--scan-type` | `connect` | See note below — only `connect` is actually implemented |
| `--udp` | off | Accepted but **not implemented** — see [Known limitations](#known-limitations--honest-status) |
| `--service` | off | Enable banner-grab + service fingerprinting on confirmed-open ports |
| `--os` | off | Enable OS detection (TTL-based; **Unix only**, see below) |
| `--retry` | 2 | Retries per port during Phase 2 confirmation |
| `--adaptive` | on | Adaptive rate backoff on timeouts/ICMP storms |
| `--timing` | `T4` | `T0`–`T5` (paranoid→insane) or named: `paranoid,sneaky,polite,normal,aggressive,insane`. Only changes the requests/sec rate — see [Known limitations](#known-limitations--honest-status) |

**Scan pipeline (what actually runs today):**
1. **Discovery** — fast concurrent TCP-connect sweep across the requested ports
2. **Confirmation** — re-verifies each candidate with TCP-connect + retries
3. **Service detection** (`--service`) — grabs a banner and matches it against an
   embedded probe database (`wordlists/service-probes.txt`, derived from
   `nmap-service-probes` format)
4. **OS detection** (`--os`) — reads the live `IP_TTL` socket option from the first
   open connection (Unix only) and matches it against an embedded fingerprint
   database. **On Windows, or if the measurement fails, this reports
   "unavailable" rather than guessing.**

**`--scan-type`:** only `connect` is implemented. Passing `syn`, `fin`, `null`,
`xmas`, or `ack` prints an explicit warning and falls back to `connect` — the
raw-socket probe/capture loop these need isn't wired up yet. This was a deliberate
choice over silently mislabeling connect-scan results as SYN-scan results.

**No root/admin needed.** Everything currently implemented uses standard TCP
connect, so it works without elevated privileges on any OS.

**Examples:**
```bash
spectre portscan -t 192.168.1.1 --all-ports
spectre portscan -t example.com -p 80,443,22,8080 --service
spectre portscan -t 10.0.0.0/24 --top-ports 1000 --os -f json -o scan.json
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

SPECTRE documents what doesn't work yet instead of silently pretending it does.
As of this writing:

| Feature | Status |
|---|---|
| `subdomain --all` | Flag is accepted and logged, but currently behaves the same as running with neither `--passive` nor `--brute`. The coverage maximizers below are not yet triggered by it. |
| Subdomain permutation / recursive enumeration / Wayback & CommonCrawl archive mining / GitHub & search-engine OSINT (`internal/enrich/*`) | **Implemented as library code but not called from any command.** Not reachable today through the CLI. |
| `dirfuzz --proxies` | Flag accepted, **not wired into the HTTP client** — requests do not currently route through the proxy file. |
| `portscan --scan-type syn/fin/null/xmas/ack` | Falls back to `connect` with an explicit warning. The raw-socket craft/send/capture loop (`utils.CraftTCP` exists, but nothing sends or listens for the responses) is not implemented. |
| `portscan --udp` | Flag accepted, UDP scanning is **not implemented**. |
| `portscan --timing` (T0–T5) | Only adjusts the requests/second rate. The jitter, decoy-IP, packet-fragmentation, and probe-order-shuffling logic in `internal/evasion/stealth.go` exists as library code but is **not called from the port scanner**. |
| `portscan --os` | Real on Unix (reads the live `IP_TTL` socket option and matches against an embedded fingerprint table). On Windows, or whenever the measurement fails, it correctly reports "unavailable" — it does not fabricate a guess. |
| WAF evasion (`dirfuzz --waf-evasion`) | **This one works** — implemented inline in `internal/dirfuzz` and verified end-to-end. |

If you need any of the not-yet-wired items for real work, say so — they're
either already half-built (enrich, evasion, raw sockets) or need to be built
from scratch (UDP scanning), and the next pass should focus on actually wiring
them into the commands rather than adding more surface area.

---

## Authorized use only

SPECTRE performs active probing (port scans, DNS brute force, directory fuzzing)
against the targets you point it at. Only run it against:
- Systems you own
- Engagements with explicit written authorization (pentest, bug bounty in scope)
- CTF/lab environments designed for this purpose

Use `--scope` to enforce an allowlist and the audit log (`~/.spectre/audit.jsonl`,
on by default) to keep a record of what was run and when.

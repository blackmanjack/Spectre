# Building SPECTRE

## Prerequisites

1. Install Go 1.22+: https://go.dev/dl/
2. On Windows, add Go to PATH (installer does this automatically)

## Build

```bash
# Download dependencies and build
go mod tidy
go build -ldflags="-s -w" -o spectre .

# On Windows
go build -ldflags="-s -w" -o spectre.exe .

# Verify no supply-chain issues
go mod verify
```

## Quick test

See [README.md](README.md) for full flag documentation and the list of
features that are accepted as flags but not yet wired up.

```bash
# Subdomain passive enumeration
./spectre subdomain -d example.com --passive

# Fast mode (head-to-head vs assetfinder)
./spectre subdomain -d example.com --fast

# DNS recon
./spectre dns example.com

# Web tech fingerprint
./spectre webtech https://example.com

# Directory fuzzing
./spectre dirfuzz -u https://example.com -x php,html

# Port scan — no root/admin needed, TCP connect is the only implemented scan type today
./spectre portscan -t 192.168.1.1 -p 80,443,22,8080 --service

# Port scan all ports with OS detection (Unix: real TTL read; Windows: reports unavailable)
./spectre portscan -t 192.168.1.1 --all-ports --service --os

# Wordlist management
./spectre wordlists list
./spectre wordlists pull raft-medium-dirs
./spectre dirfuzz -u https://example.com -w directory:medium
```

## Cross-compilation

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o spectre-linux-amd64 .

# Windows amd64
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o spectre-windows-amd64.exe .

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o spectre-darwin-arm64 .
```

## Benchmark vs assetfinder

```bash
# Install hyperfine: https://github.com/sharkdp/hyperfine
# Install assetfinder: go install github.com/tomnomnom/assetfinder@latest

hyperfine \
  "assetfinder --subs-only example.com" \
  "./spectre subdomain -d example.com --fast" \
  --runs 10 --warmup 2
```

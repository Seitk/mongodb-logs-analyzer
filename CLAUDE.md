# CLAUDE.md

## Project

mla (MongoDB Log Analyzer) — Go CLI tool that analyzes MongoDB 4.4+ JSON logs (LOGV2 format) and generates interactive HTML reports with Plotly.js charts. Optional AI synthesis via Claude CLI.

## Build & Test

```bash
make build       # Build binary → ./mla
make test        # Run all tests
make lint        # go vet
make build-all   # Cross-compile: darwin-arm64, linux-amd64, linux-arm64
make clean       # Remove artifacts
```

## Project Structure

```
cmd/mla/main.go              # CLI entry point, flag parsing, subcommand dispatch
internal/
  parser/                     # LogEntry struct, streaming scanner, query shape extraction (json2pattern)
  analyzer/                   # 10 accumulators + orchestrator (single-pass, no goroutines)
  report/                     # HTML (Plotly.js embedded), JSON output, AI synthesis
  atlas/                      # Atlas Admin API client (Digest auth, list projects/hosts, download logs)
```

## Key Conventions

- Pure Go, zero external dependencies (stdlib only)
- Go module: `github.com/Seitk/mongodb-logs-analyzer`
- All packages under `internal/` — not importable externally
- Single-pass architecture: read line → parse JSON → dispatch to each accumulator
- Plotly.js loaded via CDN in template.html (not embedded yet)
- Tests use in-memory fixtures, no external test files needed

## Important Message IDs

- 51803: Slow query (triggers slowquery, tablescan, storage, transaction accumulators)
- 22943/22944: Connection accepted/ended
- 51800: Client metadata
- 6723804: TLS handshake
- 5286306: Authentication success

## Running

```bash
# Analyze
./mla logfile.log                    # HTML report
./mla -format json logfile.log       # JSON to stdout
./mla -ai logfile.log                # With AI analysis
./mla -ai -repo ./app logfile.log    # AI + code context
./mla -slow 200 logfile.log          # Custom threshold

# Download from Atlas (requires ATLAS_PUBLIC_KEY + ATLAS_PRIVATE_KEY env vars)
./mla download -list-projects
./mla download -project <id> -list-hosts
./mla download -project <id> -host <hostname> -o logs/
```

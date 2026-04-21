# mla — MongoDB Log Analyzer

A fast, single-binary CLI tool that analyzes MongoDB 4.4+ structured JSON logs (LOGV2) and generates interactive HTML reports with Plotly.js charts. Optionally enhanced with AI-powered synthesis.

Built as a modern replacement for [mtools](https://github.com/rueckstiess/mtools), which stopped working after MongoDB 4.4 changed to JSON log format.

## Features

- **10 analysis modules** in a single pass — processes 1M lines in ~5 seconds
- **Interactive HTML report** with Plotly.js charts, sortable tables, click-to-inspect modals
- **JSON output** for piping to any AI tool or script
- **AI synthesis** via Claude CLI (or any configurable command) with optional repo code correlation
- **Zero dependencies** — pure Go, statically linked, single binary

### Analysis Modules

| Module | Description |
|--------|-------------|
| General Stats | Time range, line counts, severity/component distribution, server info |
| Slow Query Analysis | Group by query pattern, min/max/mean/p95/sum, CPU/write-concern/storage breakdown |
| Table Scan Detection | COLLSCAN and high docsExamined/nreturned ratio alerts |
| Connection Analysis | Open/close tracking, per-IP stats, TLS handshake times, connection duration pairing |
| Client Analysis | Group by driver name, version, and application name |
| Distinct Log Patterns | Message frequency analysis for spotting anomalies |
| Replica Set State | State transition tracking (PRIMARY/SECONDARY/etc.) |
| Storage Stats | Per-namespace bytes read/written and I/O time |
| Transaction Analysis | Transaction duration, read concern, active/inactive time |
| Errors & Warnings | Grouped by severity, component, and message pattern |

### HTML Report Sections

- Executive summary with key metric cards
- AI analysis & recommendations (collapsible, with severity-coded issue cards)
- Operations overview (component donut chart + message type bar chart)
- Slow queries by operation type (donut + table)
- Operations timeline (clickable — zooms all charts to that time window)
- Slow query scatter plot (clickable — shows full sample command in modal)
- Duration breakdown (CPU vs write-concern vs storage wait vs other)
- Table scan alerts
- Connection churn chart + top client IPs
- Client summary, distinct patterns, replica set state, storage stats, transactions, errors

## Quick Start

### Download

Grab the latest binary for your platform from [Releases](https://github.com/Seitk/mongodb-logs-analyzer/releases):

```bash
# macOS (Apple Silicon)
curl -Lo mla mla-darwin-arm64 && chmod +x mla

# Linux (x86_64)
curl -Lo mla mla-linux-amd64 && chmod +x mla

# Linux (ARM64)
curl -Lo mla mla-linux-arm64 && chmod +x mla
```

### Build from Source

```bash
git clone https://github.com/Seitk/mongodb-logs-analyzer.git
cd mongodb-logs-analyzer
make build    # → ./mla
```

### Usage

```bash
# Generate an HTML report (default)
mla mongod.log

# JSON output for piping
mla -format json mongod.log

# AI-enhanced report with Claude
mla -ai mongod.log

# AI analysis with application code context
mla -ai -repo ./my-app mongod.log

# Pipe JSON to any AI tool
mla -format json mongod.log | claude -p "analyze these MongoDB metrics"
mla -format json mongod.log | llm -m gpt-4 "provide recommendations"

# Custom slow query threshold (default: 100ms)
mla -slow 200 mongod.log

# Custom output path
mla -o report.html mongod.log
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-format` | `html` | Output format: `html` or `json` |
| `-o` | `<logname>_report.html` | Output file path |
| `-slow` | `100` | Slow query threshold in milliseconds |
| `-ai` | `false` | Enable AI synthesis |
| `-ai-cmd` | `claude -p` | AI command (must read stdin, write stdout) |
| `-repo` | | Application repo path for code correlation |

## Download Logs from Atlas

Pull logs directly from MongoDB Atlas using the Administration API.

### Setup

Create an API key in your Atlas organization with Project Read Only access (minimum). Then:

```bash
export ATLAS_PUBLIC_KEY=your-public-key
export ATLAS_PRIVATE_KEY=your-private-key
```

### Commands

```bash
# List all projects
mla download -list-projects

# List hosts in a project
mla download -project <projectId> -list-hosts

# Download last 24h of logs (default)
mla download -project <projectId> -host <hostname> -o logs/

# Custom time range
mla download -project <projectId> -host <hostname> \
  -start 2024-01-15T00:00:00Z -end 2024-01-15T12:00:00Z -o logs/

# Download mongos logs instead of mongod
mla download -project <projectId> -host <hostname> -log mongos -o logs/

# Then analyze
mla logs/*.log
```

### Download Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-project` | | Atlas project/group ID (required) |
| `-host` | | Hostname to download from (required) |
| `-log` | `mongodb` | Log type: `mongodb`, `mongos`, `mongodb-audit-log`, `mongos-audit-log` |
| `-o` | `.` | Output directory |
| `-start` | 24h ago | Start time (ISO 8601) |
| `-end` | now | End time (ISO 8601) |
| `-api-key` | `$ATLAS_PUBLIC_KEY` | Atlas public API key |
| `-api-secret` | `$ATLAS_PRIVATE_KEY` | Atlas private API key |
| `-list-projects` | | List available projects |
| `-list-hosts` | | List hosts in a project |

## AI Integration

When `-ai` is passed, mla:

1. Completes the full analysis
2. If `-repo` is set, scans the codebase for MongoDB collection references matching slow query namespaces
3. Sends metrics + code context to the AI command
4. Inserts the AI response as a collapsible "AI Analysis & Recommendations" section in the HTML report

The AI section includes:
- Health summary
- Critical issues with severity-coded cards (high/medium/low)
- Quick wins (actionable in <1 hour)
- Longer-term improvements

### Using Other AI Tools

The `-ai-cmd` flag accepts any command that reads from stdin and writes to stdout:

```bash
mla -ai -ai-cmd "llm -m gpt-4" mongod.log
mla -ai -ai-cmd "ollama run llama3" mongod.log
```

## Development

### Project Structure

```
mongodb-logs-analyzer/
├── cmd/mla/main.go              # CLI entry point
├── internal/
│   ├── parser/                  # Log line parsing, streaming scanner, query shape extraction
│   ├── analyzer/                # 10 analysis accumulators + orchestrator
│   ├── report/                  # HTML (Plotly.js), JSON, and AI output
│   └── atlas/                   # Atlas Admin API client (Digest auth, log download)
├── Makefile                     # build, test, lint, clean, build-all
├── Dockerfile                   # Multi-stage Alpine build
└── go.mod                       # Zero external dependencies
```

### Build Commands

```bash
make build       # Build for current platform → ./mla
make test        # Run all tests
make lint        # Run go vet
make build-all   # Cross-compile for macOS ARM64, Linux AMD64, Linux ARM64
make clean       # Remove build artifacts
```

### Docker

```bash
docker build -t mla .
docker run -v $(pwd):/data mla /data/mongod.log
```

### Architecture

Single-pass stream-and-accumulate: `bufio.Scanner` reads lines, `encoding/json` parses each into a `LogEntry`, then 10 accumulator modules process it sequentially. After the scan, results are rendered to the chosen output format. No goroutines needed — the bottleneck is I/O, not CPU.

## MongoDB Log Format

mla parses the LOGV2 structured JSON format introduced in MongoDB 4.4:

```json
{
  "t": {"$date": "2024-01-15T12:00:00.000+00:00"},
  "s": "I",
  "c": "COMMAND",
  "id": 51803,
  "ctx": "conn123",
  "msg": "Slow query",
  "attr": { "durationMillis": 150, "ns": "mydb.users", ... }
}
```

Key message IDs tracked: 51803 (slow query), 22943/22944 (connection open/close), 51800 (client metadata), 6723804 (TLS handshake), 5286306 (authentication).

## License

MIT

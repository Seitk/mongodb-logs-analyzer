# MLA — MongoDB Log Analyzer

## Overview

`mla` is a single-binary CLI tool written in Go that analyzes MongoDB 4.4+ structured JSON logs (LOGV2 format). It produces a self-contained interactive HTML report with Plotly.js charts, optionally enhanced with AI-powered synthesis via Claude CLI or any pluggable AI command.

It replaces the analysis capabilities of [mtools](https://github.com/rueckstiess/mtools) (which broke after MongoDB 4.4 changed to JSON log format) with feature parity plus additional insights from fields only available in LOGV2.

## Architecture

**Stream-and-Accumulate (single pass):** The tool reads the log file line-by-line with `bufio.Scanner`, parses each JSON line into a `LogEntry` struct, and dispatches it to multiple accumulator modules. Each accumulator maintains its own in-memory state. After the scan completes, all accumulators produce their results, which are rendered into the chosen output format.

No external Go dependencies — standard library only (`encoding/json`, `bufio`, `html/template`, `os/exec`, `math`, `sort`, `embed`).

## MongoDB LOGV2 Log Format

Each line is a JSON object following the Relaxed Extended JSON v2.0 spec:

```json
{
  "t": {"$date": "2026-04-18T12:36:15.017+00:00"},
  "s": "I",
  "c": "COMMAND",
  "id": 51803,
  "ctx": "conn55592",
  "msg": "Slow query",
  "attr": { ... }
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `t` | `{"$date": "ISO-8601"}` | Timestamp (Relaxed Extended JSON 2.0) |
| `s` | string | Severity: `F` (fatal), `E` (error), `W` (warning), `I` (info), `D1`-`D5` (debug) |
| `c` | string | Component: `NETWORK`, `COMMAND`, `ACCESS`, `STORAGE`, `WTCHKPT`, `CONNPOOL`, `REPL`, `QUERY`, `INDEX`, `WRITE`, `CONTROL`, `SHARDING`, `GEO`, `QRYSTATS`, `-` (default) |
| `id` | int32 | Unique message identifier |
| `ctx` | string | Context — connection or thread name |
| `msg` | string | Human-readable message |
| `attr` | object | Structured attributes — varies by message type |

### Key Message IDs

| ID | Message | Relevant attr fields |
|----|---------|---------------------|
| 51803 | "Slow query" | `type`, `ns`, `command`, `durationMillis`, `planSummary`, `keysExamined`, `docsExamined`, `nreturned`/`nMatched`/`nModified`/`ninserted`, `numYields`, `locks`, `storage`, `waitForWriteConcernDurationMillis`, `cpuNanos`, `flowControl`, `queues`, `appName`, `remote` |
| 22943 | "Connection accepted" | `remote`, `connectionId`, `connectionCount`, `local` |
| 22944 | "Connection ended" | `remote`, `connectionId`, `connectionCount`, `local` |
| 51800 | "client metadata" | `remote`, `client`, `doc` (driver name, version, appName, os, platform) |
| 6723804 | "Ingress TLS handshake complete" | `durationMillis` |
| 5286306 | "Successfully authenticated" | `user`, `db`, `mechanism`, `client` |
| 22430 | "WiredTiger message" | `message` (checkpoint progress, etc.) |
| 20883 | "Interrupted operation as its client disconnected" | `opId` |

### Slow Query attr Structure

```json
{
  "type": "command",
  "ns": "isi.applereceipts",
  "command": { "find": "applereceipts", "filter": { "transactionId": "..." }, ... },
  "durationMillis": 120,
  "planSummary": "IXSCAN { transactionId: 1 }",
  "keysExamined": 1,
  "docsExamined": 1,
  "nreturned": 1,
  "numYields": 0,
  "locks": { ... },
  "storage": {
    "data": { "bytesRead": 88529, "timeReadingMicros": 603 },
    "timeWaitingMicros": { "storageEngineMicros": 18 }
  },
  "waitForWriteConcernDurationMillis": 119,
  "cpuNanos": 740227,
  "flowControl": { "acquireCount": 1 },
  "queues": {
    "ingress": { "admissions": 1, "totalTimeQueuedMicros": 0 },
    "execution": { "admissions": 2, "totalTimeQueuedMicros": 0 }
  },
  "appName": "...",
  "remote": "10.7.12.254:53779"
}
```

Reference sources:
- [MongoDB Logging Developer Docs](https://github.com/mongodb/mongo/blob/master/docs/logging.md)
- [MongoDB LOGV2 README (v4.4)](https://github.com/mongodb/mongo/blob/v4.4/src/mongo/logv2/README.md)
- [MongoDB Log Parsing Spec](https://github.com/rueckstiess/mongodb-log-spec)
- [MongoDB Official Log Messages Reference](https://www.mongodb.com/docs/manual/reference/log-messages/)

## CLI Interface

```
$ mla server.log                                    # HTML report (default)
$ mla server.log --format json                      # JSON output for piping
$ mla server.log --ai --repo ./myapp                # AI-enhanced report
$ mla server.log --format json | claude -p "..."    # Composable piping
$ mla server.log --format json | llm -m gpt-4 "..." # Any AI tool
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| (positional) | string | required | Log file path |
| `--format` | string | `html` | Output format: `html` (full interactive report), `json` (structured data for piping) |
| `-o` / `--output` | string | `{logname}_report.html` | Output file path |
| `--ai` | bool | false | Enable AI synthesis via external CLI |
| `--repo` | string | "" | Path to application repo for code correlation |
| `--ai-cmd` | string | `claude -p` | Override AI command. Must accept a prompt on stdin and write the response to stdout. The metrics JSON + code context is piped as stdin. |
| `--slow` | int | 100 | Slow query threshold in milliseconds |

## Analysis Modules

All modules are called sequentially within a single pass through the log file. Each line is parsed once into a `LogEntry`, then dispatched to each accumulator's `Process(entry)` method in turn. No goroutines — the loop is: read line → parse JSON → call each accumulator. This keeps the code simple and avoids synchronization overhead (the bottleneck is I/O, not CPU).

### 1. General Stats

Equivalent to mtools `mloginfo` base header output.

**Collected:**
- Time range (first and last timestamp)
- Total line count
- Lines by severity (`F`, `E`, `W`, `I`, `D1`-`D5`)
- Lines by component
- Top 20 message types by frequency
- Server info: host, port, replSet, binary (mongod/mongos), version, storage engine, clusterRole
- Server restarts (detected via startup messages)

### 2. Slow Query Analysis

Equivalent to mtools `mloginfo --queries`, with additional LOGV2-only metrics.

**Grouping key:** `(namespace, operation type, command name, query shape, allowDiskUse)`

**Per group:**
| Metric | Computation |
|--------|-------------|
| count | Total events in group |
| min (ms) | `min(durationMillis)` |
| max (ms) | `max(durationMillis)` |
| mean (ms) | `sum / count` |
| p95 (ms) | 95th percentile of `durationMillis` (sorted-slice) |
| sum (ms) | `sum(durationMillis)` |
| mean cpuNanos | Mean of `cpuNanos` — **beyond mtools** |
| mean writeConcernWait (ms) | Mean of `waitForWriteConcernDurationMillis` — **beyond mtools** |
| mean storageWait (us) | Mean of `storage.timeWaitingMicros.storageEngineMicros` — **beyond mtools** |
| mean queueTime (us) | Mean of `queues.execution.totalTimeQueuedMicros` — **beyond mtools** |
| sample command | One full example command per group for debugging |

**Query shape extraction (json2pattern):** Walk the `command.filter` (or `command.pipeline` for aggregates) object. Replace all leaf values with `1`. Sort keys alphabetically at every level. Preserve operators (`$gt`, `$in`, `$exists`, etc.). Produces a deterministic, comparable pattern string.

**Operation types recognized:** query, getmore, insert, update, remove, command, aggregate, find, findAndModify, count, distinct, geoNear, mapReduce, delete.

### 3. Table Scan Detection

Equivalent to mtools `mlogfilter --scan`, plus planSummary-based detection.

**Detection criteria (any of):**
- `planSummary` contains `COLLSCAN`
- `docsExamined > 10000` AND `docsExamined / nreturned > 100`

**Output per detection:**
- Timestamp, namespace, operation, planSummary
- docsExamined, keysExamined, nreturned, durationMillis
- Sample command

### 4. Connection Analysis

Equivalent to mtools `mloginfo --connections` + `--connstats` + mplotqueries `connchurn`.

**Collected:**
- Total opened (id=22943) / closed (id=22944)
- `connectionCount` over time (sampled at each event, bucketed into 1-minute intervals for charting)
- Per-IP breakdown: connection count, first/last seen
- Connection duration pairing: match open/close events by `connectionId`, compute duration per connection
- TLS handshake times (id=6723804): min/max/mean/p95 of `durationMillis`

### 5. Client Analysis

Equivalent to mtools `mloginfo --clients`.

**Grouping key:** `(driver name, driver version, appName)` extracted from client metadata (id=51800) `attr.doc`.

**Per group:**
- Connection count
- List of unique remote IPs
- List of authenticated users (cross-referenced with id=5286306 by connId)

### 6. Distinct Log Patterns

Equivalent to mtools `mloginfo --distinct`.

**Grouping key:** `msg` field value.

**Per group:**
- Count
- First/last seen timestamp
- Example `attr` (one sample)

Sorted by count descending. Useful for spotting unusual or rare message patterns.

### 7. Replica Set State

Equivalent to mtools `mloginfo --rsstate`.

**Detected events:**
- Replica set state transitions (PRIMARY, SECONDARY, ARBITER, RECOVERING, STARTUP, etc.)
- Detected from msg patterns: "Transition to ...", state change related messages

**Per event:** timestamp, old state, new state, host.

### 8. Storage Stats

Equivalent to mtools `mloginfo --storagestats`.

**Per namespace (from slow query attr.storage):**
- Total bytesRead, bytesWritten
- Total timeReadingMicros, timeWritingMicros
- Operation count
- Mean bytes per operation

### 9. Transaction Analysis

Equivalent to mtools `mloginfo --transactions`.

**Detected from:** slow query entries where `attr.command` contains `txnNumber`, or msg contains "transaction".

**Per transaction event:**
- Timestamp, txnNumber, namespace
- durationMillis, readConcern level
- timeActiveMicros, timeInactiveMicros (if present)
- terminationCause (if present)

### 10. Errors & Warnings

**Collected:** All entries with severity `E`, `W`, or `F`.

**Grouping key:** `(severity, component, msg)`

**Per group:**
- Count
- First/last occurrence timestamp
- Sample `attr`

## HTML Report Layout

Single self-contained HTML file with embedded Plotly.js (~3.5MB, or partial bundle ~1MB limited to: scatter/scattergl, bar, line, pie, heatmap).

### Sections (top to bottom)

1. **Header** — hostname, time range, MongoDB version, replica set, storage engine, binary
2. **Executive Summary** — key numbers in cards: total lines, slow query count, error count, peak connections, table scans detected, time range
3. **Operations Timeline** — Plotly line chart: events per minute stacked by component. Data zoom for time range selection.
4. **Slow Query Analysis** — Sortable HTML table (namespace, pattern, count, min/max/mean/p95/sum). Click row to expand and show sample command. Sortable by any column.
5. **Slow Query Scatter Plot** — Plotly `scattergl`: dots over time, y-axis = durationMillis, colored by namespace. Handles thousands of points via WebGL.
6. **Duration Breakdown** — Plotly stacked horizontal bar for top 20 query patterns: segments for CPU time, write-concern wait, storage wait, other. Shows where time is actually spent.
7. **Table Scan Alerts** — Red-highlighted table of queries with COLLSCAN or high scan ratio. Sorted by durationMillis descending.
8. **Connection Analysis** — Plotly stacked area chart: opened/closed/total connections over time (1-min buckets). Plus top-IPs table.
9. **Client Summary** — Table grouped by driver/version/appName with connection counts.
10. **Distinct Log Patterns** — Frequency table of unique `msg` values, sorted by count descending.
11. **Replica Set State** — Timeline of state transitions (if any detected).
12. **Storage Stats** — Per-namespace I/O table: bytesRead, bytesWritten, timeReading, timeWriting.
13. **Transactions** — Table of transaction events (if any present).
14. **Errors & Warnings** — Grouped by message pattern, with counts and timestamps.
15. **AI Analysis** (if `--ai` flag) — Synthesized insights and actionable recommendations from Claude or configured AI tool.

### Interactivity

- All Plotly charts: hover tooltips, zoom, pan, lasso select, export to PNG/SVG
- Linked time axes across charts: zooming in the Operations Timeline updates the x-axis range on the Scatter Plot and Connection chart
- Sortable tables: click column headers to sort
- Expandable rows: click slow query row to see full sample command
- Dark/light theme toggle

## AI Integration

### `--ai` mode

When `--ai` is passed:

1. The Go tool completes its analysis and produces the metrics JSON
2. If `--repo` is provided, the tool scans the repo for MongoDB query patterns:
   - Grep for collection names that appear in slow query namespaces
   - Grep for `.find(`, `.aggregate(`, `.updateOne(`, `.insertMany(`, etc.
   - Include matching file paths + surrounding code snippets (5 lines of context)
3. Build a prompt combining metrics + code context
4. Execute the AI command (`claude -p` by default, or `--ai-cmd` override) with the prompt on stdin
5. Insert the AI response as the "AI Analysis" section in the HTML report

### Prompt structure

```
You are analyzing MongoDB server logs for a production database. Here are the 
analysis results from a {duration} window on {host} ({version}, {replSet}).

## Key Metrics
{metrics_json}

## Application Code Context
{code_snippets_if_repo_provided}

## Instructions
Provide:
1. Executive summary (3-5 sentences covering overall health)
2. Top issues ranked by severity and impact:
   - For each: root cause analysis, supporting evidence from metrics,
     and a specific actionable fix (index creation commands, code changes, 
     config recommendations)
3. Quick wins (can fix in <1 hour) vs. longer-term improvements
4. Any concerning patterns or trends
```

### Composable mode

Without `--ai`, the `--format json` output is designed for piping:

```bash
# Pipe to Claude
mla server.log --format json | claude -p "analyze these MongoDB metrics"

# Pipe to any other tool
mla server.log --format json | llm -m gpt-4 "provide recommendations"

# Use as input to a Claude Code skill
mla server.log --format json | my-custom-analysis-skill
```

## Project Structure

```
mongodb-logs-analyzer/
├── main.go                     # CLI entry point, flag parsing
├── parser/
│   ├── logentry.go             # LogEntry struct, JSON unmarshaling
│   ├── scanner.go              # Streaming line scanner
│   └── pattern.go              # Query shape extraction (json2pattern)
├── analyzer/
│   ├── analyzer.go             # Orchestrator — dispatches lines to accumulators
│   ├── general.go              # General stats accumulator
│   ├── slowquery.go            # Slow query grouping + percentile computation
│   ├── tablescan.go            # COLLSCAN / high docsExamined detection
│   ├── connection.go           # Connection open/close tracking
│   ├── client.go               # Driver/version/appName grouping
│   ├── distinct.go             # Distinct message pattern frequency
│   ├── rsstate.go              # Replica set state transitions
│   ├── storage.go              # Per-namespace I/O stats
│   ├── transaction.go          # Transaction analysis
│   └── errors.go               # Error/warning collection
├── report/
│   ├── html.go                 # HTML report generator
│   ├── json.go                 # JSON output formatter
│   ├── template.go             # Embedded HTML/Plotly.js template
│   └── ai.go                   # AI synthesis (subprocess invocation)
├── go.mod
└── go.sum
```

## Testing Strategy

- **Unit tests** per analyzer module with crafted JSON log lines
- **Integration test** against the real log file: `gn-shop-prod-shard-00-02.pumxn.mongodb.net_2026-04-18T12_37_07_2026-04-18T16_37_07_MONGODB.log` (957K lines, 348MB)
  - Verify line count matches `wc -l`
  - Verify slow query count matches `grep -c '"Slow query"'` (239)
  - Verify connection accepted count matches `grep -c '"Connection accepted"'`
  - Verify HTML report is valid and contains expected sections
  - Verify JSON output is valid JSON and contains all expected keys
- **Benchmark** parse speed on the real log file — target: under 10 seconds for the full 348MB file

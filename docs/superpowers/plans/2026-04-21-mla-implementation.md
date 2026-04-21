# MLA (MongoDB Log Analyzer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go CLI tool (`mla`) that analyzes MongoDB 4.4+ JSON logs and produces interactive HTML reports with Plotly.js, with optional AI synthesis.

**Architecture:** Single-pass stream-and-accumulate. `bufio.Scanner` reads lines, `encoding/json` parses each into a `LogEntry`, and 10 accumulator modules each maintain in-memory state. After the scan, results are rendered to HTML (Plotly.js embedded) or JSON. Optional `--ai` flag shells out to `claude -p` or configurable command.

**Tech Stack:** Go 1.20+ (stdlib only: `encoding/json`, `bufio`, `html/template`, `os/exec`, `embed`, `flag`, `math`, `sort`), Plotly.js (embedded via `//go:embed`)

**Spec:** `docs/superpowers/specs/2026-04-21-mongodb-log-analyzer-design.md`

**Verification targets from the real log file** (`sample-shard-00-02_2026-04-18T12_37_07_2026-04-18T16_37_07_MONGODB.log`, 348MB):
- Total lines: 956,777
- Slow queries (id=51803): 239
- Connection accepted (id=22943): 155,318
- Connection ended (id=22944): 149,377
- Client metadata (id=51800): 154,275
- Auth success (id=5286306): 147,582
- Warnings (s=W): 11
- Errors (s=E): 0
- COLLSCAN occurrences: 2
- RS state transitions: 0
- Lines containing "transaction": 81

---

## File Structure

```
mongodb-logs-analyzer/
├── main.go                        # CLI entry point: flag parsing, orchestration
├── parser/
│   ├── logentry.go                # LogEntry struct + JSON unmarshaling + timestamp parsing
│   ├── logentry_test.go           # Unit tests for LogEntry parsing
│   ├── scanner.go                 # Streaming line scanner wrapping bufio.Scanner
│   ├── scanner_test.go            # Unit tests for scanner
│   ├── pattern.go                 # json2pattern: query shape extraction
│   └── pattern_test.go            # Unit tests for pattern extraction
├── analyzer/
│   ├── analyzer.go                # Accumulator interface + orchestrator that dispatches entries
│   ├── general.go                 # General stats: time range, counts, severity, component
│   ├── general_test.go
│   ├── slowquery.go               # Slow query grouping, percentiles, duration breakdown
│   ├── slowquery_test.go
│   ├── tablescan.go               # COLLSCAN and high-ratio detection
│   ├── tablescan_test.go
│   ├── connection.go              # Connection open/close, per-IP, timeline buckets
│   ├── connection_test.go
│   ├── client.go                  # Driver/version/appName grouping
│   ├── client_test.go
│   ├── distinct.go                # Distinct msg pattern frequency
│   ├── distinct_test.go
│   ├── rsstate.go                 # Replica set state transitions
│   ├── rsstate_test.go
│   ├── storage.go                 # Per-namespace bytesRead/Written stats
│   ├── storage_test.go
│   ├── transaction.go             # Transaction analysis
│   ├── transaction_test.go
│   ├── errors.go                  # Error/warning collection
│   └── errors_test.go
├── report/
│   ├── json.go                    # JSON output formatter
│   ├── json_test.go
│   ├── html.go                    # HTML report generator using html/template
│   ├── html_test.go
│   ├── template.html              # Embedded HTML template with Plotly.js
│   └── ai.go                      # AI synthesis: subprocess invocation + repo scanning
├── testdata/
│   └── (created by tests, not committed)
├── go.mod
└── main_test.go                   # Integration test against real log file
```

---

### Task 1: Project Scaffold + LogEntry Parser

**Files:**
- Create: `go.mod`
- Create: `parser/logentry.go`
- Create: `parser/logentry_test.go`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer
go mod init github.com/Seitk/mongodb-logs-analyzer
```

- [ ] **Step 2: Write failing test for LogEntry parsing**

Create `parser/logentry_test.go`:

```go
package parser

import (
	"testing"
	"time"
)

func TestParseLogEntry_SlowQuery(t *testing.T) {
	raw := `{"t":{"$date":"2026-04-18T12:50:44.119+00:00"},"s":"I",  "c":"COMMAND",  "id":51803,   "ctx":"conn56141","msg":"Slow query","attr":{"type":"command","ns":"config.$cmd","command":{"update":"availability","updates":[{"q":{"_id":"1"},"u":{"$inc":{"seq":1}}}]},"durationMillis":101,"planSummary":"IXSCAN { _id: 1 }","keysExamined":1,"docsExamined":1,"numYields":0,"nreturned":0,"nModified":1,"cpuNanos":238554,"waitForWriteConcernDurationMillis":80,"storage":{"data":{"bytesRead":100,"timeReadingMicros":50},"timeWaitingMicros":{"storageEngineMicros":17}},"queues":{"execution":{"totalTimeQueuedMicros":5}},"appName":"TestApp","remote":"10.0.0.1:5000"}}`

	entry, err := ParseLogEntry([]byte(raw))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if entry.Timestamp.Year() != 2026 {
		t.Errorf("timestamp year = %d, want 2026", entry.Timestamp.Year())
	}
	if entry.Severity != "I" {
		t.Errorf("severity = %q, want %q", entry.Severity, "I")
	}
	if entry.Component != "COMMAND" {
		t.Errorf("component = %q, want %q", entry.Component, "COMMAND")
	}
	if entry.ID != 51803 {
		t.Errorf("id = %d, want 51803", entry.ID)
	}
	if entry.Context != "conn56141" {
		t.Errorf("ctx = %q, want %q", entry.Context, "conn56141")
	}
	if entry.Message != "Slow query" {
		t.Errorf("msg = %q, want %q", entry.Message, "Slow query")
	}
	if entry.Attr == nil {
		t.Fatal("attr is nil")
	}
}

func TestParseLogEntry_ConnectionAccepted(t *testing.T) {
	raw := `{"t":{"$date":"2026-04-18T12:36:15.018+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,   "ctx":"listener","msg":"Connection accepted","attr":{"remote":"127.0.0.1:57380","connectionId":55617,"connectionCount":15524,"local":"127.0.0.1:27017"}}`

	entry, err := ParseLogEntry([]byte(raw))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if entry.ID != 22943 {
		t.Errorf("id = %d, want 22943", entry.ID)
	}
	if entry.Message != "Connection accepted" {
		t.Errorf("msg = %q, want %q", entry.Message, "Connection accepted")
	}
}

func TestParseLogEntry_TimestampParsing(t *testing.T) {
	raw := `{"t":{"$date":"2026-04-18T12:36:15.574+00:00"},"s":"I","c":"-","id":1,"ctx":"test","msg":"test"}`

	entry, err := ParseLogEntry([]byte(raw))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	expected := time.Date(2026, 4, 18, 12, 36, 15, 574000000, time.UTC)
	if !entry.Timestamp.Equal(expected) {
		t.Errorf("timestamp = %v, want %v", entry.Timestamp, expected)
	}
}

func TestParseLogEntry_SeverityWhitespace(t *testing.T) {
	raw := `{"t":{"$date":"2026-04-18T12:36:15.574+00:00"},"s":"I",  "c":"NETWORK",  "id":1,"ctx":"test","msg":"test"}`

	entry, err := ParseLogEntry([]byte(raw))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if entry.Component != "NETWORK" {
		t.Errorf("component = %q, want %q (whitespace not trimmed?)", entry.Component, "NETWORK")
	}
}

func TestParseLogEntry_InvalidJSON(t *testing.T) {
	_, err := ParseLogEntry([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./parser/ -v -run TestParseLogEntry
```

Expected: FAIL — `ParseLogEntry` not defined.

- [ ] **Step 4: Implement LogEntry struct and parser**

Create `parser/logentry.go`:

```go
package parser

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type LogEntry struct {
	Timestamp time.Time
	Severity  string
	Component string
	ID        int
	Context   string
	Message   string
	Attr      map[string]interface{}
}

type rawEntry struct {
	T   rawTimestamp            `json:"t"`
	S   string                 `json:"s"`
	C   string                 `json:"c"`
	ID  int                    `json:"id"`
	Ctx string                 `json:"ctx"`
	Msg string                 `json:"msg"`
	Attr map[string]interface{} `json:"attr"`
}

type rawTimestamp struct {
	Date string `json:"$date"`
}

func ParseLogEntry(line []byte) (LogEntry, error) {
	var raw rawEntry
	if err := json.Unmarshal(line, &raw); err != nil {
		return LogEntry{}, fmt.Errorf("json unmarshal: %w", err)
	}

	ts, err := time.Parse(time.RFC3339Nano, raw.T.Date)
	if err != nil {
		ts, err = time.Parse("2006-01-02T15:04:05.000-07:00", raw.T.Date)
		if err != nil {
			return LogEntry{}, fmt.Errorf("timestamp parse %q: %w", raw.T.Date, err)
		}
	}

	return LogEntry{
		Timestamp: ts,
		Severity:  strings.TrimSpace(raw.S),
		Component: strings.TrimSpace(raw.C),
		ID:        raw.ID,
		Context:   raw.Ctx,
		Message:   raw.Msg,
		Attr:      raw.Attr,
	}, nil
}

func (e *LogEntry) AttrString(key string) string {
	if e.Attr == nil {
		return ""
	}
	v, ok := e.Attr[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

func (e *LogEntry) AttrInt(key string) int {
	if e.Attr == nil {
		return 0
	}
	v, ok := e.Attr[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func (e *LogEntry) AttrFloat(key string) float64 {
	if e.Attr == nil {
		return 0
	}
	v, ok := e.Attr[key]
	if !ok {
		return 0
	}
	n, ok := v.(float64)
	if !ok {
		return 0
	}
	return n
}

func (e *LogEntry) AttrMap(key string) map[string]interface{} {
	if e.Attr == nil {
		return nil
	}
	v, ok := e.Attr[key]
	if !ok {
		return nil
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./parser/ -v -run TestParseLogEntry
```

Expected: all 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod parser/logentry.go parser/logentry_test.go
git commit -m "feat: add LogEntry parser with JSON unmarshaling and timestamp parsing"
```

---

### Task 2: Line Scanner

**Files:**
- Create: `parser/scanner.go`
- Create: `parser/scanner_test.go`

- [ ] **Step 1: Write failing test for scanner**

Create `parser/scanner_test.go`:

```go
package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner_BasicLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	content := `{"t":{"$date":"2026-04-18T12:36:15.000+00:00"},"s":"I","c":"-","id":1,"ctx":"test","msg":"line1"}
{"t":{"$date":"2026-04-18T12:36:16.000+00:00"},"s":"W","c":"QUERY","id":2,"ctx":"test","msg":"line2"}
{"t":{"$date":"2026-04-18T12:36:17.000+00:00"},"s":"E","c":"COMMAND","id":3,"ctx":"test","msg":"line3"}
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	var entries []LogEntry
	err := ScanFile(path, func(entry LogEntry) {
		entries = append(entries, entry)
	})
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Message != "line1" {
		t.Errorf("entry[0].msg = %q, want %q", entries[0].Message, "line1")
	}
	if entries[1].Severity != "W" {
		t.Errorf("entry[1].severity = %q, want %q", entries[1].Severity, "W")
	}
	if entries[2].Component != "COMMAND" {
		t.Errorf("entry[2].component = %q, want %q", entries[2].Component, "COMMAND")
	}
}

func TestScanner_SkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	content := `not json at all
{"t":{"$date":"2026-04-18T12:36:15.000+00:00"},"s":"I","c":"-","id":1,"ctx":"test","msg":"valid"}
also not json
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	var entries []LogEntry
	err := ScanFile(path, func(entry LogEntry) {
		entries = append(entries, entry)
	})
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (skip malformed)", len(entries))
	}
}

func TestScanner_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	var count int
	err := ScanFile(path, func(entry LogEntry) {
		count++
	})
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if count != 0 {
		t.Errorf("got %d entries, want 0", count)
	}
}

func TestScanner_FileNotFound(t *testing.T) {
	err := ScanFile("/nonexistent/file.log", func(entry LogEntry) {})
	if err == nil {
		t.Error("expected error for missing file")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./parser/ -v -run TestScanner
```

Expected: FAIL — `ScanFile` not defined.

- [ ] **Step 3: Implement scanner**

Create `parser/scanner.go`:

```go
package parser

import (
	"bufio"
	"fmt"
	"os"
)

const maxLineSize = 1024 * 1024 // 1MB max line size

func ScanFile(path string, callback func(LogEntry)) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		entry, err := ParseLogEntry(line)
		if err != nil {
			continue // skip malformed lines
		}
		callback(entry)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./parser/ -v -run TestScanner
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add parser/scanner.go parser/scanner_test.go
git commit -m "feat: add streaming log file scanner with malformed line skip"
```

---

### Task 3: Query Shape Extraction (json2pattern)

**Files:**
- Create: `parser/pattern.go`
- Create: `parser/pattern_test.go`

- [ ] **Step 1: Write failing test for pattern extraction**

Create `parser/pattern_test.go`:

```go
package parser

import (
	"testing"
)

func TestExtractPattern_SimpleFilter(t *testing.T) {
	cmd := map[string]interface{}{
		"find": "users",
		"filter": map[string]interface{}{
			"email": "test@example.com",
		},
	}
	name, shape := ExtractPattern(cmd)
	if name != "find" {
		t.Errorf("name = %q, want %q", name, "find")
	}
	if shape != `{"email":1}` {
		t.Errorf("shape = %q, want %q", shape, `{"email":1}`)
	}
}

func TestExtractPattern_NestedOperators(t *testing.T) {
	cmd := map[string]interface{}{
		"find": "orders",
		"filter": map[string]interface{}{
			"status": map[string]interface{}{
				"$in": []interface{}{"active", "pending"},
			},
			"amount": map[string]interface{}{
				"$gt": 100.0,
			},
		},
	}
	_, shape := ExtractPattern(cmd)
	if shape != `{"amount":{"$gt":1},"status":{"$in":1}}` {
		t.Errorf("shape = %q, want %q", shape, `{"amount":{"$gt":1},"status":{"$in":1}}`)
	}
}

func TestExtractPattern_Update(t *testing.T) {
	cmd := map[string]interface{}{
		"update": "availability",
		"updates": []interface{}{
			map[string]interface{}{
				"q": map[string]interface{}{
					"_id": "000000000000000001",
				},
				"u": map[string]interface{}{
					"$inc": map[string]interface{}{"seq": 1.0},
				},
			},
		},
	}
	name, shape := ExtractPattern(cmd)
	if name != "update" {
		t.Errorf("name = %q, want %q", name, "update")
	}
	if shape != `{"_id":1}` {
		t.Errorf("shape = %q, want %q", shape, `{"_id":1}`)
	}
}

func TestExtractPattern_Insert(t *testing.T) {
	cmd := map[string]interface{}{
		"insert": "events",
		"documents": []interface{}{
			map[string]interface{}{"_id": "abc", "name": "test"},
		},
	}
	name, shape := ExtractPattern(cmd)
	if name != "insert" {
		t.Errorf("name = %q, want %q", name, "insert")
	}
	if shape != "" {
		t.Errorf("shape = %q, want empty (inserts have no filter)", shape)
	}
}

func TestExtractPattern_Aggregate(t *testing.T) {
	cmd := map[string]interface{}{
		"aggregate": "subscriptions",
		"pipeline": []interface{}{
			map[string]interface{}{
				"$match": map[string]interface{}{
					"status": "active",
				},
			},
			map[string]interface{}{
				"$group": map[string]interface{}{
					"_id": "$userId",
					"count": map[string]interface{}{"$sum": 1.0},
				},
			},
		},
	}
	name, shape := ExtractPattern(cmd)
	if name != "aggregate" {
		t.Errorf("name = %q, want %q", name, "aggregate")
	}
	if shape != `[{"$group":{"_id":1,"count":{"$sum":1}}},{"$match":{"status":1}}]` {
		t.Errorf("shape = %q, want pipeline pattern", shape)
	}
}

func TestExtractPattern_SortedKeys(t *testing.T) {
	cmd := map[string]interface{}{
		"find": "test",
		"filter": map[string]interface{}{
			"z_field": "val",
			"a_field": "val",
			"m_field": "val",
		},
	}
	_, shape := ExtractPattern(cmd)
	if shape != `{"a_field":1,"m_field":1,"z_field":1}` {
		t.Errorf("shape = %q, want sorted keys", shape, `{"a_field":1,"m_field":1,"z_field":1}`)
	}
}

func TestExtractPattern_EmptyCommand(t *testing.T) {
	name, shape := ExtractPattern(nil)
	if name != "" || shape != "" {
		t.Errorf("expected empty for nil command, got name=%q shape=%q", name, shape)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./parser/ -v -run TestExtractPattern
```

Expected: FAIL — `ExtractPattern` not defined.

- [ ] **Step 3: Implement pattern extraction**

Create `parser/pattern.go`:

```go
package parser

import (
	"encoding/json"
	"sort"
)

var commandNames = []string{
	"find", "aggregate", "insert", "update", "delete",
	"findAndModify", "count", "distinct", "geoNear",
	"mapReduce", "getMore", "create", "drop",
	"createIndexes", "dropIndexes", "collMod",
}

func ExtractPattern(cmd map[string]interface{}) (name string, shape string) {
	if cmd == nil {
		return "", ""
	}

	for _, cn := range commandNames {
		if _, ok := cmd[cn]; ok {
			name = cn
			break
		}
	}
	if name == "" {
		for k := range cmd {
			if k != "$db" && k != "$clusterTime" && k != "lsid" && k != "$readPreference" && k != "maxTimeMS" && k != "txnNumber" && k != "autocommit" && k != "startTransaction" && k != "readConcern" && k != "writeConcern" {
				name = k
				break
			}
		}
	}

	switch name {
	case "find", "count", "distinct":
		if filter, ok := cmd["filter"].(map[string]interface{}); ok {
			shape = patternJSON(normalizeShape(filter))
		}
	case "update":
		if updates, ok := cmd["updates"].([]interface{}); ok && len(updates) > 0 {
			if first, ok := updates[0].(map[string]interface{}); ok {
				if q, ok := first["q"].(map[string]interface{}); ok {
					shape = patternJSON(normalizeShape(q))
				}
			}
		}
	case "delete":
		if deletes, ok := cmd["deletes"].([]interface{}); ok && len(deletes) > 0 {
			if first, ok := deletes[0].(map[string]interface{}); ok {
				if q, ok := first["q"].(map[string]interface{}); ok {
					shape = patternJSON(normalizeShape(q))
				}
			}
		}
	case "findAndModify":
		if query, ok := cmd["query"].(map[string]interface{}); ok {
			shape = patternJSON(normalizeShape(query))
		}
	case "aggregate":
		if pipeline, ok := cmd["pipeline"].([]interface{}); ok {
			shape = patternJSON(normalizePipeline(pipeline))
		}
	}

	return name, shape
}

func normalizeShape(doc map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range doc {
		switch val := v.(type) {
		case map[string]interface{}:
			if isOperatorDoc(val) {
				result[k] = normalizeShape(val)
			} else {
				result[k] = 1
			}
		default:
			result[k] = 1
		}
	}
	return result
}

func isOperatorDoc(doc map[string]interface{}) bool {
	for k := range doc {
		if len(k) > 0 && k[0] == '$' {
			return true
		}
	}
	return false
}

func normalizePipeline(pipeline []interface{}) []interface{} {
	var stages []interface{}
	for _, stage := range pipeline {
		if stageMap, ok := stage.(map[string]interface{}); ok {
			normalized := make(map[string]interface{})
			for k, v := range stageMap {
				switch val := v.(type) {
				case map[string]interface{}:
					normalized[k] = normalizeShape(val)
				default:
					normalized[k] = 1
				}
			}
			stages = append(stages, normalized)
		}
	}
	sort.Slice(stages, func(i, j int) bool {
		a, _ := json.Marshal(stages[i])
		b, _ := json.Marshal(stages[j])
		return string(a) < string(b)
	})
	return stages
}

func patternJSON(v interface{}) string {
	b, err := marshalSorted(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func marshalSorted(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, _ := json.Marshal(k)
			buf = append(buf, kb...)
			buf = append(buf, ':')
			vb, err := marshalSorted(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil
	case []interface{}:
		buf := []byte{'['}
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			ib, err := marshalSorted(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, ib...)
		}
		buf = append(buf, ']')
		return buf, nil
	default:
		return json.Marshal(v)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./parser/ -v -run TestExtractPattern
```

Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add parser/pattern.go parser/pattern_test.go
git commit -m "feat: add query shape extraction (json2pattern) for slow query grouping"
```

---

### Task 4: Accumulator Interface + Orchestrator

**Files:**
- Create: `analyzer/analyzer.go`

- [ ] **Step 1: Create the Accumulator interface and orchestrator**

Create `analyzer/analyzer.go`:

```go
package analyzer

import (
	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type Accumulator interface {
	Process(entry parser.LogEntry)
}

type Results struct {
	General      GeneralResult
	SlowQueries  SlowQueryResult
	TableScans   TableScanResult
	Connections  ConnectionResult
	Clients      ClientResult
	Distinct     DistinctResult
	RSState      RSStateResult
	Storage      StorageResult
	Transactions TransactionResult
	Errors       ErrorResult
}

type Analyzer struct {
	general      *GeneralAccumulator
	slowQuery    *SlowQueryAccumulator
	tableScan    *TableScanAccumulator
	connection   *ConnectionAccumulator
	client       *ClientAccumulator
	distinct     *DistinctAccumulator
	rsState      *RSStateAccumulator
	storage      *StorageAccumulator
	transaction  *TransactionAccumulator
	errors       *ErrorAccumulator
	slowMS       int
}

func New(slowMS int) *Analyzer {
	return &Analyzer{
		general:     NewGeneralAccumulator(),
		slowQuery:   NewSlowQueryAccumulator(),
		tableScan:   NewTableScanAccumulator(),
		connection:  NewConnectionAccumulator(),
		client:      NewClientAccumulator(),
		distinct:    NewDistinctAccumulator(),
		rsState:     NewRSStateAccumulator(),
		storage:     NewStorageAccumulator(),
		transaction: NewTransactionAccumulator(),
		errors:      NewErrorAccumulator(),
		slowMS:      slowMS,
	}
}

func (a *Analyzer) Process(entry parser.LogEntry) {
	a.general.Process(entry)
	a.distinct.Process(entry)
	a.errors.Process(entry)
	a.connection.Process(entry)
	a.client.Process(entry)
	a.rsState.Process(entry)

	if entry.ID == 51803 {
		dur := entry.AttrInt("durationMillis")
		if dur >= a.slowMS {
			a.slowQuery.Process(entry)
		}
		a.tableScan.Process(entry)
		a.storage.Process(entry)
		a.transaction.Process(entry)
	}
}

func (a *Analyzer) Finalize() Results {
	return Results{
		General:      a.general.Result(),
		SlowQueries:  a.slowQuery.Result(),
		TableScans:   a.tableScan.Result(),
		Connections:  a.connection.Result(),
		Clients:      a.client.Result(),
		Distinct:     a.distinct.Result(),
		RSState:      a.rsState.Result(),
		Storage:      a.storage.Result(),
		Transactions: a.transaction.Result(),
		Errors:       a.errors.Result(),
	}
}

func (a *Analyzer) Run(path string) (Results, error) {
	err := parser.ScanFile(path, func(entry parser.LogEntry) {
		a.Process(entry)
	})
	if err != nil {
		return Results{}, err
	}
	return a.Finalize(), nil
}
```

This file won't compile until the accumulator types exist. We'll build them in subsequent tasks, testing each individually.

- [ ] **Step 2: Commit (partial — will compile after Task 5-14)**

```bash
git add analyzer/analyzer.go
git commit -m "feat: add accumulator interface and analysis orchestrator (skeleton)"
```

---

### Task 5: General Stats Accumulator

**Files:**
- Create: `analyzer/general.go`
- Create: `analyzer/general_test.go`

- [ ] **Step 1: Write failing test**

Create `analyzer/general_test.go`:

```go
package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

func makeEntry(ts string, severity, component string, id int, msg string) parser.LogEntry {
	t, _ := time.Parse(time.RFC3339Nano, ts)
	return parser.LogEntry{
		Timestamp: t,
		Severity:  severity,
		Component: component,
		ID:        id,
		Context:   "test",
		Message:   msg,
	}
}

func TestGeneralAccumulator_BasicStats(t *testing.T) {
	acc := NewGeneralAccumulator()

	acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "I", "NETWORK", 22943, "Connection accepted"))
	acc.Process(makeEntry("2026-04-18T12:00:01.000Z", "W", "QUERY", 23799, "Aggregate command executor error"))
	acc.Process(makeEntry("2026-04-18T12:00:02.000Z", "I", "COMMAND", 51803, "Slow query"))
	acc.Process(makeEntry("2026-04-18T12:00:03.000Z", "I", "NETWORK", 22944, "Connection ended"))
	acc.Process(makeEntry("2026-04-18T13:00:00.000Z", "E", "STORAGE", 100, "Some error"))

	r := acc.Result()

	if r.TotalLines != 5 {
		t.Errorf("TotalLines = %d, want 5", r.TotalLines)
	}
	if r.SeverityCounts["I"] != 3 {
		t.Errorf("SeverityCounts[I] = %d, want 3", r.SeverityCounts["I"])
	}
	if r.SeverityCounts["W"] != 1 {
		t.Errorf("SeverityCounts[W] = %d, want 1", r.SeverityCounts["W"])
	}
	if r.SeverityCounts["E"] != 1 {
		t.Errorf("SeverityCounts[E] = %d, want 1", r.SeverityCounts["E"])
	}
	if r.ComponentCounts["NETWORK"] != 2 {
		t.Errorf("ComponentCounts[NETWORK] = %d, want 2", r.ComponentCounts["NETWORK"])
	}
	if r.StartTime.Year() != 2026 {
		t.Errorf("StartTime year = %d, want 2026", r.StartTime.Year())
	}
	if r.EndTime.Sub(r.StartTime) != time.Hour {
		t.Errorf("duration = %v, want 1h", r.EndTime.Sub(r.StartTime))
	}
}

func TestGeneralAccumulator_MessageFrequency(t *testing.T) {
	acc := NewGeneralAccumulator()

	for i := 0; i < 10; i++ {
		acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "I", "NETWORK", 22943, "Connection accepted"))
	}
	for i := 0; i < 3; i++ {
		acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "I", "COMMAND", 51803, "Slow query"))
	}

	r := acc.Result()

	if len(r.TopMessages) == 0 {
		t.Fatal("TopMessages is empty")
	}
	if r.TopMessages[0].Message != "Connection accepted" || r.TopMessages[0].Count != 10 {
		t.Errorf("TopMessages[0] = %+v, want Connection accepted:10", r.TopMessages[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestGeneralAccumulator -count=1 2>&1 | head -20
```

Expected: FAIL — types not defined.

- [ ] **Step 3: Implement general stats accumulator**

Create `analyzer/general.go`:

```go
package analyzer

import (
	"sort"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type MessageCount struct {
	Message string
	Count   int
}

type GeneralResult struct {
	TotalLines      int
	StartTime       time.Time
	EndTime         time.Time
	SeverityCounts  map[string]int
	ComponentCounts map[string]int
	TopMessages     []MessageCount
	Host            string
	ReplicaSet      string
	Version         string
	Binary          string
	StorageEngine   string
}

type GeneralAccumulator struct {
	totalLines      int
	startTime       time.Time
	endTime         time.Time
	severityCounts  map[string]int
	componentCounts map[string]int
	messageCounts   map[string]int
	host            string
	replicaSet      string
	version         string
	binary          string
	storageEngine   string
}

func NewGeneralAccumulator() *GeneralAccumulator {
	return &GeneralAccumulator{
		severityCounts:  make(map[string]int),
		componentCounts: make(map[string]int),
		messageCounts:   make(map[string]int),
	}
}

func (a *GeneralAccumulator) Process(entry parser.LogEntry) {
	a.totalLines++

	if a.totalLines == 1 || entry.Timestamp.Before(a.startTime) {
		a.startTime = entry.Timestamp
	}
	if entry.Timestamp.After(a.endTime) {
		a.endTime = entry.Timestamp
	}

	a.severityCounts[entry.Severity]++
	a.componentCounts[entry.Component]++
	a.messageCounts[entry.Message]++

	// Extract server info from known message IDs
	switch entry.ID {
	case 23403: // "Environment. Host"
		if h := entry.AttrString("host"); h != "" {
			a.host = h
		}
	case 21752: // "Replica set config"
		if rs := entry.AttrString("replSetName"); rs != "" {
			a.replicaSet = rs
		}
	case 23299: // "db version"
		if v := entry.AttrString("version"); v != "" {
			a.version = v
		}
	case 23400: // "Binary"
		if b := entry.AttrString("binary"); b != "" {
			a.binary = b
		}
	case 22315: // "Opening WiredTiger"
		a.storageEngine = "wiredTiger"
	}
}

func (a *GeneralAccumulator) Result() GeneralResult {
	msgs := make([]MessageCount, 0, len(a.messageCounts))
	for msg, count := range a.messageCounts {
		msgs = append(msgs, MessageCount{Message: msg, Count: count})
	}
	sort.Slice(msgs, func(i, j int) bool {
		return msgs[i].Count > msgs[j].Count
	})
	if len(msgs) > 20 {
		msgs = msgs[:20]
	}

	return GeneralResult{
		TotalLines:      a.totalLines,
		StartTime:       a.startTime,
		EndTime:         a.endTime,
		SeverityCounts:  a.severityCounts,
		ComponentCounts: a.componentCounts,
		TopMessages:     msgs,
		Host:            a.host,
		ReplicaSet:      a.replicaSet,
		Version:         a.version,
		Binary:          a.binary,
		StorageEngine:   a.storageEngine,
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestGeneralAccumulator -count=1
```

Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add analyzer/general.go analyzer/general_test.go
git commit -m "feat: add general stats accumulator (time range, severity, component, msg frequency)"
```

---

### Task 6: Slow Query Accumulator

**Files:**
- Create: `analyzer/slowquery.go`
- Create: `analyzer/slowquery_test.go`

- [ ] **Step 1: Write failing test**

Create `analyzer/slowquery_test.go`:

```go
package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

func makeSlowQueryEntry(ns string, durationMs float64, cmdName string, filter map[string]interface{}, cpuNanos, writeConcernMs, storageWaitUs, queueUs float64) parser.LogEntry {
	cmd := map[string]interface{}{
		cmdName: "coll",
	}
	if filter != nil {
		cmd["filter"] = filter
	}

	attr := map[string]interface{}{
		"ns":            ns,
		"type":          "command",
		"command":       cmd,
		"durationMillis": durationMs,
		"cpuNanos":      cpuNanos,
		"waitForWriteConcernDurationMillis": writeConcernMs,
		"storage": map[string]interface{}{
			"timeWaitingMicros": map[string]interface{}{
				"storageEngineMicros": storageWaitUs,
			},
		},
		"queues": map[string]interface{}{
			"execution": map[string]interface{}{
				"totalTimeQueuedMicros": queueUs,
			},
		},
	}

	ts, _ := time.Parse(time.RFC3339Nano, "2026-04-18T12:00:00.000Z")
	return parser.LogEntry{
		Timestamp: ts,
		Severity:  "I",
		Component: "COMMAND",
		ID:        51803,
		Context:   "conn1",
		Message:   "Slow query",
		Attr:      attr,
	}
}

func TestSlowQueryAccumulator_Grouping(t *testing.T) {
	acc := NewSlowQueryAccumulator()

	filter := map[string]interface{}{"email": "x"}
	acc.Process(makeSlowQueryEntry("db.users", 100, "find", filter, 1000000, 10, 5, 2))
	acc.Process(makeSlowQueryEntry("db.users", 200, "find", filter, 2000000, 20, 10, 4))
	acc.Process(makeSlowQueryEntry("db.users", 300, "find", filter, 3000000, 30, 15, 6))
	acc.Process(makeSlowQueryEntry("db.orders", 150, "find", nil, 500000, 5, 3, 1))

	r := acc.Result()

	if len(r.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(r.Groups))
	}

	var usersGroup *SlowQueryGroup
	for i := range r.Groups {
		if r.Groups[i].Namespace == "db.users" {
			usersGroup = &r.Groups[i]
		}
	}
	if usersGroup == nil {
		t.Fatal("missing db.users group")
	}

	if usersGroup.Count != 3 {
		t.Errorf("count = %d, want 3", usersGroup.Count)
	}
	if usersGroup.MinMs != 100 {
		t.Errorf("min = %d, want 100", usersGroup.MinMs)
	}
	if usersGroup.MaxMs != 300 {
		t.Errorf("max = %d, want 300", usersGroup.MaxMs)
	}
	if usersGroup.SumMs != 600 {
		t.Errorf("sum = %d, want 600", usersGroup.SumMs)
	}
	if usersGroup.MeanMs != 200 {
		t.Errorf("mean = %d, want 200", usersGroup.MeanMs)
	}
}

func TestSlowQueryAccumulator_P95(t *testing.T) {
	acc := NewSlowQueryAccumulator()

	filter := map[string]interface{}{"x": 1}
	for i := 1; i <= 100; i++ {
		acc.Process(makeSlowQueryEntry("db.test", float64(i), "find", filter, 0, 0, 0, 0))
	}

	r := acc.Result()
	if len(r.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(r.Groups))
	}

	g := r.Groups[0]
	if g.P95Ms < 95 || g.P95Ms > 96 {
		t.Errorf("p95 = %d, want ~95", g.P95Ms)
	}
}

func TestSlowQueryAccumulator_Timeline(t *testing.T) {
	acc := NewSlowQueryAccumulator()

	for i := 0; i < 5; i++ {
		e := makeSlowQueryEntry("db.test", 100, "find", nil, 0, 0, 0, 0)
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, "2026-04-18T12:00:30.000Z")
		acc.Process(e)
	}
	for i := 0; i < 3; i++ {
		e := makeSlowQueryEntry("db.test", 200, "find", nil, 0, 0, 0, 0)
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, "2026-04-18T12:01:30.000Z")
		acc.Process(e)
	}

	r := acc.Result()
	if len(r.Timeline) < 2 {
		t.Fatalf("timeline has %d buckets, want >= 2", len(r.Timeline))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestSlowQueryAccumulator -count=1 2>&1 | head -10
```

Expected: FAIL — types not defined.

- [ ] **Step 3: Implement slow query accumulator**

Create `analyzer/slowquery.go`:

```go
package analyzer

import (
	"sort"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type SlowQueryGroup struct {
	Namespace       string
	Operation       string
	CommandName     string
	Pattern         string
	AllowDiskUse    bool
	Count           int
	MinMs           int
	MaxMs           int
	MeanMs          int
	P95Ms           int
	SumMs           int
	MeanCPUNanos    int64
	MeanWriteConcernMs int
	MeanStorageWaitUs  int
	MeanQueueUs     int
	SampleCommand   map[string]interface{}
	durations       []int
	cpuNanosSum     int64
	writeConcernSum int64
	storageWaitSum  int64
	queueSum        int64
}

type TimelineBucket struct {
	Time  time.Time
	Count int
}

type SlowQueryResult struct {
	Groups   []SlowQueryGroup
	Timeline []TimelineBucket
}

type SlowQueryAccumulator struct {
	groups   map[string]*SlowQueryGroup
	timeline map[int64]int // unix minute -> count
}

func NewSlowQueryAccumulator() *SlowQueryAccumulator {
	return &SlowQueryAccumulator{
		groups:   make(map[string]*SlowQueryGroup),
		timeline: make(map[int64]int),
	}
}

func (a *SlowQueryAccumulator) Process(entry parser.LogEntry) {
	ns := entry.AttrString("ns")
	opType := entry.AttrString("type")
	cmd := entry.AttrMap("command")
	cmdName, pattern := parser.ExtractPattern(cmd)
	dur := entry.AttrInt("durationMillis")

	allowDiskUse := false
	if v, ok := entry.Attr["allowDiskUse"]; ok {
		if b, ok := v.(bool); ok {
			allowDiskUse = b
		}
	}
	diskStr := ""
	if allowDiskUse {
		diskStr = "|disk"
	}
	key := ns + "|" + opType + "|" + cmdName + "|" + pattern + diskStr
	g, ok := a.groups[key]
	if !ok {
		g = &SlowQueryGroup{
			Namespace:    ns,
			Operation:    opType,
			CommandName:  cmdName,
			Pattern:      pattern,
			AllowDiskUse: allowDiskUse,
			MinMs:        dur,
			MaxMs:        dur,
		}
		a.groups[key] = g
	}

	g.Count++
	g.durations = append(g.durations, dur)
	g.SumMs += dur
	if dur < g.MinMs {
		g.MinMs = dur
	}
	if dur > g.MaxMs {
		g.MaxMs = dur
	}

	g.cpuNanosSum += int64(entry.AttrFloat("cpuNanos"))
	g.writeConcernSum += int64(entry.AttrFloat("waitForWriteConcernDurationMillis"))

	if storage := entry.AttrMap("storage"); storage != nil {
		if tw, ok := storage["timeWaitingMicros"].(map[string]interface{}); ok {
			if sem, ok := tw["storageEngineMicros"].(float64); ok {
				g.storageWaitSum += int64(sem)
			}
		}
	}
	if queues := entry.AttrMap("queues"); queues != nil {
		if exec, ok := queues["execution"].(map[string]interface{}); ok {
			if tq, ok := exec["totalTimeQueuedMicros"].(float64); ok {
				g.queueSum += int64(tq)
			}
		}
	}

	if g.SampleCommand == nil {
		g.SampleCommand = cmd
	}

	minuteKey := entry.Timestamp.Truncate(time.Minute).Unix()
	a.timeline[minuteKey]++
}

func (a *SlowQueryAccumulator) Result() SlowQueryResult {
	groups := make([]SlowQueryGroup, 0, len(a.groups))
	for _, g := range a.groups {
		g.MeanMs = g.SumMs / g.Count
		g.P95Ms = percentile(g.durations, 95)
		g.MeanCPUNanos = g.cpuNanosSum / int64(g.Count)
		g.MeanWriteConcernMs = int(g.writeConcernSum / int64(g.Count))
		g.MeanStorageWaitUs = int(g.storageWaitSum / int64(g.Count))
		g.MeanQueueUs = int(g.queueSum / int64(g.Count))
		g.durations = nil // free memory
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].SumMs > groups[j].SumMs
	})

	timeline := make([]TimelineBucket, 0, len(a.timeline))
	for ts, count := range a.timeline {
		timeline = append(timeline, TimelineBucket{
			Time:  time.Unix(ts, 0).UTC(),
			Count: count,
		})
	}
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Time.Before(timeline[j].Time)
	})

	return SlowQueryResult{Groups: groups, Timeline: timeline}
}

func percentile(values []int, pct int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]int, len(values))
	copy(sorted, values)
	sort.Ints(sorted)
	idx := (pct * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestSlowQueryAccumulator -count=1
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add analyzer/slowquery.go analyzer/slowquery_test.go
git commit -m "feat: add slow query accumulator with pattern grouping, p95, and duration breakdown"
```

---

### Task 7: Table Scan Accumulator

**Files:**
- Create: `analyzer/tablescan.go`
- Create: `analyzer/tablescan_test.go`

- [ ] **Step 1: Write failing test**

Create `analyzer/tablescan_test.go`:

```go
package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

func makeSlowQueryWithPlan(ns string, planSummary string, docsExamined, nreturned, durationMs int) parser.LogEntry {
	attr := map[string]interface{}{
		"ns":            ns,
		"type":          "command",
		"durationMillis": float64(durationMs),
		"planSummary":   planSummary,
		"docsExamined":  float64(docsExamined),
		"keysExamined":  float64(0),
		"command":       map[string]interface{}{"find": "test", "filter": map[string]interface{}{"x": 1}},
	}
	if nreturned > 0 {
		attr["nreturned"] = float64(nreturned)
	}

	ts, _ := time.Parse(time.RFC3339Nano, "2026-04-18T12:00:00.000Z")
	return parser.LogEntry{
		Timestamp: ts, Severity: "I", Component: "COMMAND",
		ID: 51803, Context: "conn1", Message: "Slow query", Attr: attr,
	}
}

func TestTableScanAccumulator_COLLSCAN(t *testing.T) {
	acc := NewTableScanAccumulator()
	acc.Process(makeSlowQueryWithPlan("db.users", "COLLSCAN", 5000, 5000, 500))

	r := acc.Result()
	if len(r.Scans) != 1 {
		t.Fatalf("got %d scans, want 1", len(r.Scans))
	}
	if r.Scans[0].Namespace != "db.users" {
		t.Errorf("ns = %q, want %q", r.Scans[0].Namespace, "db.users")
	}
}

func TestTableScanAccumulator_HighRatio(t *testing.T) {
	acc := NewTableScanAccumulator()
	acc.Process(makeSlowQueryWithPlan("db.orders", "IXSCAN { status: 1 }", 50000, 10, 200))

	r := acc.Result()
	if len(r.Scans) != 1 {
		t.Fatalf("got %d scans, want 1 (ratio 5000:1)", len(r.Scans))
	}
}

func TestTableScanAccumulator_NoDetection(t *testing.T) {
	acc := NewTableScanAccumulator()
	acc.Process(makeSlowQueryWithPlan("db.users", "IXSCAN { _id: 1 }", 1, 1, 100))

	r := acc.Result()
	if len(r.Scans) != 0 {
		t.Errorf("got %d scans, want 0", len(r.Scans))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestTableScanAccumulator -count=1 2>&1 | head -10
```

- [ ] **Step 3: Implement table scan accumulator**

Create `analyzer/tablescan.go`:

```go
package analyzer

import (
	"sort"
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type TableScan struct {
	Timestamp    time.Time
	Namespace    string
	PlanSummary  string
	DocsExamined int
	KeysExamined int
	NReturned    int
	DurationMs   int
	Command      map[string]interface{}
}

type TableScanResult struct {
	Scans []TableScan
}

type TableScanAccumulator struct {
	scans []TableScan
}

func NewTableScanAccumulator() *TableScanAccumulator {
	return &TableScanAccumulator{}
}

func (a *TableScanAccumulator) Process(entry parser.LogEntry) {
	plan := entry.AttrString("planSummary")
	docsExamined := entry.AttrInt("docsExamined")
	nreturned := entry.AttrInt("nreturned")

	isCollScan := strings.Contains(plan, "COLLSCAN")
	isHighRatio := docsExamined > 10000 && nreturned > 0 && docsExamined/nreturned > 100

	if !isCollScan && !isHighRatio {
		return
	}

	a.scans = append(a.scans, TableScan{
		Timestamp:    entry.Timestamp,
		Namespace:    entry.AttrString("ns"),
		PlanSummary:  plan,
		DocsExamined: docsExamined,
		KeysExamined: entry.AttrInt("keysExamined"),
		NReturned:    nreturned,
		DurationMs:   entry.AttrInt("durationMillis"),
		Command:      entry.AttrMap("command"),
	})
}

func (a *TableScanAccumulator) Result() TableScanResult {
	sort.Slice(a.scans, func(i, j int) bool {
		return a.scans[i].DurationMs > a.scans[j].DurationMs
	})
	return TableScanResult{Scans: a.scans}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestTableScanAccumulator -count=1
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add analyzer/tablescan.go analyzer/tablescan_test.go
git commit -m "feat: add table scan detection (COLLSCAN + high docsExamined ratio)"
```

---

### Task 8: Connection Accumulator

**Files:**
- Create: `analyzer/connection.go`
- Create: `analyzer/connection_test.go`

- [ ] **Step 1: Write failing test**

Create `analyzer/connection_test.go`:

```go
package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

func makeConnEntry(id int, msg string, ts string, remote string, connID float64, connCount float64) parser.LogEntry {
	t, _ := time.Parse(time.RFC3339Nano, ts)
	return parser.LogEntry{
		Timestamp: t, Severity: "I", Component: "NETWORK",
		ID: id, Context: "listener", Message: msg,
		Attr: map[string]interface{}{
			"remote":          remote,
			"connectionId":    connID,
			"connectionCount": connCount,
		},
	}
}

func TestConnectionAccumulator_OpenClose(t *testing.T) {
	acc := NewConnectionAccumulator()

	acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:00:00.000Z", "10.0.0.1:5000", 1, 10))
	acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:00:01.000Z", "10.0.0.2:5001", 2, 11))
	acc.Process(makeConnEntry(22944, "Connection ended", "2026-04-18T12:00:02.000Z", "10.0.0.1:5000", 1, 10))

	r := acc.Result()

	if r.TotalOpened != 2 {
		t.Errorf("TotalOpened = %d, want 2", r.TotalOpened)
	}
	if r.TotalClosed != 1 {
		t.Errorf("TotalClosed = %d, want 1", r.TotalClosed)
	}
}

func TestConnectionAccumulator_PerIP(t *testing.T) {
	acc := NewConnectionAccumulator()

	for i := 0; i < 5; i++ {
		acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:00:00.000Z", "10.0.0.1:5000", float64(i), 10))
	}
	for i := 0; i < 3; i++ {
		acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:00:00.000Z", "10.0.0.2:6000", float64(10+i), 10))
	}

	r := acc.Result()

	if len(r.ByIP) < 2 {
		t.Fatalf("ByIP has %d entries, want >= 2", len(r.ByIP))
	}
	if r.ByIP[0].IP != "10.0.0.1" || r.ByIP[0].Count != 5 {
		t.Errorf("top IP = %+v, want 10.0.0.1:5", r.ByIP[0])
	}
}

func TestConnectionAccumulator_Timeline(t *testing.T) {
	acc := NewConnectionAccumulator()

	acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:00:30.000Z", "10.0.0.1:5000", 1, 100))
	acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:01:30.000Z", "10.0.0.1:5000", 2, 101))

	r := acc.Result()

	if len(r.Timeline) < 2 {
		t.Fatalf("timeline has %d buckets, want >= 2", len(r.Timeline))
	}
}

func TestConnectionAccumulator_PeakConnections(t *testing.T) {
	acc := NewConnectionAccumulator()

	acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:00:00.000Z", "10.0.0.1:5000", 1, 100))
	acc.Process(makeConnEntry(22943, "Connection accepted", "2026-04-18T12:00:01.000Z", "10.0.0.1:5000", 2, 200))
	acc.Process(makeConnEntry(22944, "Connection ended", "2026-04-18T12:00:02.000Z", "10.0.0.1:5000", 1, 150))

	r := acc.Result()
	if r.PeakConnections != 200 {
		t.Errorf("PeakConnections = %d, want 200", r.PeakConnections)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestConnectionAccumulator -count=1 2>&1 | head -10
```

- [ ] **Step 3: Implement connection accumulator**

Create `analyzer/connection.go`:

```go
package analyzer

import (
	"sort"
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type IPStats struct {
	IP        string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

type ConnTimelineBucket struct {
	Time            time.Time
	Opened          int
	Closed          int
	ConnectionCount int
}

type TLSStats struct {
	Count   int
	MinMs   int
	MaxMs   int
	SumMs   int
	MeanMs  int
	P95Ms   int
	values  []int
}

type ConnectionResult struct {
	TotalOpened     int
	TotalClosed     int
	PeakConnections int
	ByIP            []IPStats
	Timeline        []ConnTimelineBucket
	TLS             TLSStats
}

type ConnectionAccumulator struct {
	totalOpened     int
	totalClosed     int
	peakConnections int
	byIP            map[string]*IPStats
	timeline        map[int64]*ConnTimelineBucket
	tlsDurations    []int
	openConns       map[int]time.Time // connectionId -> open time for duration pairing
	connDurations   []int
}

func NewConnectionAccumulator() *ConnectionAccumulator {
	return &ConnectionAccumulator{
		byIP:      make(map[string]*IPStats),
		timeline:  make(map[int64]*ConnTimelineBucket),
		openConns: make(map[int]time.Time),
	}
}

func (a *ConnectionAccumulator) Process(entry parser.LogEntry) {
	// TLS handshake tracking
	if entry.ID == 6723804 {
		dur := entry.AttrInt("durationMillis")
		a.tlsDurations = append(a.tlsDurations, dur)
		return
	}

	if entry.ID != 22943 && entry.ID != 22944 {
		return
	}

	connCount := entry.AttrInt("connectionCount")
	if connCount > a.peakConnections {
		a.peakConnections = connCount
	}

	minuteKey := entry.Timestamp.Truncate(time.Minute).Unix()
	bucket, ok := a.timeline[minuteKey]
	if !ok {
		bucket = &ConnTimelineBucket{Time: entry.Timestamp.Truncate(time.Minute)}
		a.timeline[minuteKey] = bucket
	}
	bucket.ConnectionCount = connCount

	remote := entry.AttrString("remote")
	ip := remote
	if idx := strings.LastIndex(remote, ":"); idx > 0 {
		ip = remote[:idx]
	}

	connID := entry.AttrInt("connectionId")

	if entry.ID == 22943 {
		a.totalOpened++
		bucket.Opened++
		a.openConns[connID] = entry.Timestamp

		stats, ok := a.byIP[ip]
		if !ok {
			stats = &IPStats{IP: ip, FirstSeen: entry.Timestamp}
			a.byIP[ip] = stats
		}
		stats.Count++
		stats.LastSeen = entry.Timestamp
	} else {
		a.totalClosed++
		bucket.Closed++
		if openTime, ok := a.openConns[connID]; ok {
			durMs := int(entry.Timestamp.Sub(openTime).Milliseconds())
			a.connDurations = append(a.connDurations, durMs)
			delete(a.openConns, connID)
		}
	}
}

func (a *ConnectionAccumulator) Result() ConnectionResult {
	byIP := make([]IPStats, 0, len(a.byIP))
	for _, stats := range a.byIP {
		byIP = append(byIP, *stats)
	}
	sort.Slice(byIP, func(i, j int) bool {
		return byIP[i].Count > byIP[j].Count
	})

	timeline := make([]ConnTimelineBucket, 0, len(a.timeline))
	for _, bucket := range a.timeline {
		timeline = append(timeline, *bucket)
	}
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Time.Before(timeline[j].Time)
	})

	var tls TLSStats
	if len(a.tlsDurations) > 0 {
		tls.Count = len(a.tlsDurations)
		tls.MinMs = a.tlsDurations[0]
		tls.MaxMs = a.tlsDurations[0]
		for _, d := range a.tlsDurations {
			tls.SumMs += d
			if d < tls.MinMs { tls.MinMs = d }
			if d > tls.MaxMs { tls.MaxMs = d }
		}
		tls.MeanMs = tls.SumMs / tls.Count
		tls.P95Ms = percentile(a.tlsDurations, 95)
	}

	return ConnectionResult{
		TotalOpened:     a.totalOpened,
		TotalClosed:     a.totalClosed,
		PeakConnections: a.peakConnections,
		ByIP:            byIP,
		Timeline:        timeline,
		TLS:             tls,
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestConnectionAccumulator -count=1
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add analyzer/connection.go analyzer/connection_test.go
git commit -m "feat: add connection accumulator with per-IP stats, timeline, peak tracking"
```

---

### Task 9: Remaining Accumulators (Client, Distinct, RSState, Storage, Transaction, Errors)

**Files:**
- Create: `analyzer/client.go`, `analyzer/client_test.go`
- Create: `analyzer/distinct.go`, `analyzer/distinct_test.go`
- Create: `analyzer/rsstate.go`, `analyzer/rsstate_test.go`
- Create: `analyzer/storage.go`, `analyzer/storage_test.go`
- Create: `analyzer/transaction.go`, `analyzer/transaction_test.go`
- Create: `analyzer/errors.go`, `analyzer/errors_test.go`

These six accumulators follow the same pattern. Each sub-step below creates one accumulator + test, then commits.

#### 9a: Client Accumulator

- [ ] **Step 1: Write test for client accumulator**

Create `analyzer/client_test.go`:

```go
package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

func makeClientMetadataEntry(remote, driverName, driverVersion, appName string) parser.LogEntry {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-04-18T12:00:00.000Z")
	return parser.LogEntry{
		Timestamp: ts, Severity: "I", Component: "NETWORK",
		ID: 51800, Context: "conn1", Message: "client metadata",
		Attr: map[string]interface{}{
			"remote": remote,
			"client": "conn1",
			"doc": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":    driverName,
					"version": driverVersion,
				},
				"application": map[string]interface{}{
					"name": appName,
				},
			},
		},
	}
}

func TestClientAccumulator_Grouping(t *testing.T) {
	acc := NewClientAccumulator()

	acc.Process(makeClientMetadataEntry("10.0.0.1:5000", "mongo-go-driver", "v1.12.0", "MyApp"))
	acc.Process(makeClientMetadataEntry("10.0.0.2:5001", "mongo-go-driver", "v1.12.0", "MyApp"))
	acc.Process(makeClientMetadataEntry("10.0.0.3:5002", "nodejs", "4.0.0", "OtherApp"))

	r := acc.Result()
	if len(r.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(r.Groups))
	}
}
```

- [ ] **Step 2: Implement client accumulator**

Create `analyzer/client.go`:

```go
package analyzer

import (
	"sort"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type ClientGroup struct {
	DriverName    string
	DriverVersion string
	AppName       string
	Count         int
	UniqueIPs     []string
}

type ClientResult struct {
	Groups []ClientGroup
}

type ClientAccumulator struct {
	groups map[string]*ClientGroup
	ips    map[string]map[string]bool
}

func NewClientAccumulator() *ClientAccumulator {
	return &ClientAccumulator{
		groups: make(map[string]*ClientGroup),
		ips:    make(map[string]map[string]bool),
	}
}

func (a *ClientAccumulator) Process(entry parser.LogEntry) {
	if entry.ID != 51800 {
		return
	}

	doc := entry.AttrMap("doc")
	if doc == nil {
		return
	}

	var driverName, driverVersion, appName string
	if driver, ok := doc["driver"].(map[string]interface{}); ok {
		if n, ok := driver["name"].(string); ok {
			driverName = n
		}
		if v, ok := driver["version"].(string); ok {
			driverVersion = v
		}
	}
	if app, ok := doc["application"].(map[string]interface{}); ok {
		if n, ok := app["name"].(string); ok {
			appName = n
		}
	}

	key := driverName + "|" + driverVersion + "|" + appName
	g, ok := a.groups[key]
	if !ok {
		g = &ClientGroup{
			DriverName:    driverName,
			DriverVersion: driverVersion,
			AppName:       appName,
		}
		a.groups[key] = g
		a.ips[key] = make(map[string]bool)
	}
	g.Count++

	remote := entry.AttrString("remote")
	a.ips[key][remote] = true
}

func (a *ClientAccumulator) Result() ClientResult {
	groups := make([]ClientGroup, 0, len(a.groups))
	for key, g := range a.groups {
		ips := make([]string, 0, len(a.ips[key]))
		for ip := range a.ips[key] {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		g.UniqueIPs = ips
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})
	return ClientResult{Groups: groups}
}
```

- [ ] **Step 3: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestClientAccumulator -count=1
git add analyzer/client.go analyzer/client_test.go
git commit -m "feat: add client accumulator (driver/version/appName grouping)"
```

#### 9b: Distinct Accumulator

- [ ] **Step 4: Write test + implement distinct accumulator**

Create `analyzer/distinct_test.go`:

```go
package analyzer

import (
	"testing"
)

func TestDistinctAccumulator_Frequency(t *testing.T) {
	acc := NewDistinctAccumulator()

	for i := 0; i < 10; i++ {
		acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "I", "NETWORK", 22943, "Connection accepted"))
	}
	for i := 0; i < 3; i++ {
		acc.Process(makeEntry("2026-04-18T12:00:01.000Z", "I", "COMMAND", 51803, "Slow query"))
	}

	r := acc.Result()
	if len(r.Patterns) != 2 {
		t.Fatalf("got %d patterns, want 2", len(r.Patterns))
	}
	if r.Patterns[0].Message != "Connection accepted" || r.Patterns[0].Count != 10 {
		t.Errorf("top pattern = %+v, want Connection accepted:10", r.Patterns[0])
	}
}
```

Create `analyzer/distinct.go`:

```go
package analyzer

import (
	"sort"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type DistinctPattern struct {
	Message    string
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	SampleAttr map[string]interface{}
}

type DistinctResult struct {
	Patterns []DistinctPattern
}

type DistinctAccumulator struct {
	patterns map[string]*DistinctPattern
}

func NewDistinctAccumulator() *DistinctAccumulator {
	return &DistinctAccumulator{
		patterns: make(map[string]*DistinctPattern),
	}
}

func (a *DistinctAccumulator) Process(entry parser.LogEntry) {
	p, ok := a.patterns[entry.Message]
	if !ok {
		p = &DistinctPattern{
			Message:   entry.Message,
			FirstSeen: entry.Timestamp,
			LastSeen:  entry.Timestamp,
		}
		a.patterns[entry.Message] = p
	}
	p.Count++
	if entry.Timestamp.After(p.LastSeen) {
		p.LastSeen = entry.Timestamp
	}
	if p.SampleAttr == nil && entry.Attr != nil {
		p.SampleAttr = entry.Attr
	}
}

func (a *DistinctAccumulator) Result() DistinctResult {
	patterns := make([]DistinctPattern, 0, len(a.patterns))
	for _, p := range a.patterns {
		patterns = append(patterns, *p)
	}
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Count > patterns[j].Count
	})
	return DistinctResult{Patterns: patterns}
}
```

- [ ] **Step 5: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestDistinctAccumulator -count=1
git add analyzer/distinct.go analyzer/distinct_test.go
git commit -m "feat: add distinct log pattern accumulator"
```

#### 9c: RS State Accumulator

- [ ] **Step 6: Write test + implement RS state accumulator**

Create `analyzer/rsstate_test.go`:

```go
package analyzer

import "testing"

func TestRSStateAccumulator_NoTransitions(t *testing.T) {
	acc := NewRSStateAccumulator()
	acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "I", "NETWORK", 22943, "Connection accepted"))

	r := acc.Result()
	if len(r.Transitions) != 0 {
		t.Errorf("got %d transitions, want 0", len(r.Transitions))
	}
}

func TestRSStateAccumulator_DetectsTransition(t *testing.T) {
	acc := NewRSStateAccumulator()
	acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "I", "REPL", 21358, "Transition to PRIMARY complete; database writes are now permitted"))

	r := acc.Result()
	if len(r.Transitions) != 1 {
		t.Fatalf("got %d transitions, want 1", len(r.Transitions))
	}
}
```

Create `analyzer/rsstate.go`:

```go
package analyzer

import (
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type RSTransition struct {
	Timestamp time.Time
	Message   string
}

type RSStateResult struct {
	Transitions []RSTransition
}

type RSStateAccumulator struct {
	transitions []RSTransition
}

func NewRSStateAccumulator() *RSStateAccumulator {
	return &RSStateAccumulator{}
}

func (a *RSStateAccumulator) Process(entry parser.LogEntry) {
	if entry.Component != "REPL" {
		return
	}
	msg := strings.ToLower(entry.Message)
	if strings.Contains(msg, "transition") || strings.Contains(msg, "state change") {
		a.transitions = append(a.transitions, RSTransition{
			Timestamp: entry.Timestamp,
			Message:   entry.Message,
		})
	}
}

func (a *RSStateAccumulator) Result() RSStateResult {
	return RSStateResult{Transitions: a.transitions}
}
```

- [ ] **Step 7: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestRSStateAccumulator -count=1
git add analyzer/rsstate.go analyzer/rsstate_test.go
git commit -m "feat: add replica set state transition accumulator"
```

#### 9d: Storage Accumulator

- [ ] **Step 8: Write test + implement storage accumulator**

Create `analyzer/storage_test.go`:

```go
package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

func makeStorageEntry(ns string, bytesRead, bytesWritten, timeReadUs, timeWriteUs float64) parser.LogEntry {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-04-18T12:00:00.000Z")
	return parser.LogEntry{
		Timestamp: ts, Severity: "I", Component: "COMMAND",
		ID: 51803, Context: "conn1", Message: "Slow query",
		Attr: map[string]interface{}{
			"ns": ns,
			"storage": map[string]interface{}{
				"data": map[string]interface{}{
					"bytesRead":        bytesRead,
					"bytesWritten":     bytesWritten,
					"timeReadingMicros":  timeReadUs,
					"timeWritingMicros":  timeWriteUs,
				},
			},
		},
	}
}

func TestStorageAccumulator_PerNamespace(t *testing.T) {
	acc := NewStorageAccumulator()
	acc.Process(makeStorageEntry("db.users", 1000, 500, 100, 50))
	acc.Process(makeStorageEntry("db.users", 2000, 300, 200, 30))
	acc.Process(makeStorageEntry("db.orders", 500, 0, 50, 0))

	r := acc.Result()
	if len(r.ByNamespace) != 2 {
		t.Fatalf("got %d namespaces, want 2", len(r.ByNamespace))
	}
}
```

Create `analyzer/storage.go`:

```go
package analyzer

import (
	"sort"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type NamespaceStorage struct {
	Namespace         string
	TotalBytesRead    int64
	TotalBytesWritten int64
	TotalTimeReadUs   int64
	TotalTimeWriteUs  int64
	OpCount           int
	MeanBytesRead     int64
	MeanBytesWritten  int64
}

type StorageResult struct {
	ByNamespace []NamespaceStorage
}

type StorageAccumulator struct {
	byNS map[string]*NamespaceStorage
}

func NewStorageAccumulator() *StorageAccumulator {
	return &StorageAccumulator{byNS: make(map[string]*NamespaceStorage)}
}

func (a *StorageAccumulator) Process(entry parser.LogEntry) {
	ns := entry.AttrString("ns")
	storage := entry.AttrMap("storage")
	if storage == nil {
		return
	}

	data, _ := storage["data"].(map[string]interface{})
	if data == nil {
		return
	}

	s, ok := a.byNS[ns]
	if !ok {
		s = &NamespaceStorage{Namespace: ns}
		a.byNS[ns] = s
	}
	s.OpCount++

	if v, ok := data["bytesRead"].(float64); ok {
		s.TotalBytesRead += int64(v)
	}
	if v, ok := data["bytesWritten"].(float64); ok {
		s.TotalBytesWritten += int64(v)
	}
	if v, ok := data["timeReadingMicros"].(float64); ok {
		s.TotalTimeReadUs += int64(v)
	}
	if v, ok := data["timeWritingMicros"].(float64); ok {
		s.TotalTimeWriteUs += int64(v)
	}
}

func (a *StorageAccumulator) Result() StorageResult {
	result := make([]NamespaceStorage, 0, len(a.byNS))
	for _, s := range a.byNS {
		if s.OpCount > 0 {
			s.MeanBytesRead = s.TotalBytesRead / int64(s.OpCount)
			s.MeanBytesWritten = s.TotalBytesWritten / int64(s.OpCount)
		}
		result = append(result, *s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalBytesRead > result[j].TotalBytesRead
	})
	return StorageResult{ByNamespace: result}
}
```

- [ ] **Step 9: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestStorageAccumulator -count=1
git add analyzer/storage.go analyzer/storage_test.go
git commit -m "feat: add per-namespace storage I/O accumulator"
```

#### 9e: Transaction Accumulator

- [ ] **Step 10: Write test + implement transaction accumulator**

Create `analyzer/transaction_test.go`:

```go
package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

func TestTransactionAccumulator_DetectsTxn(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-04-18T12:00:00.000Z")
	entry := parser.LogEntry{
		Timestamp: ts, Severity: "I", Component: "COMMAND",
		ID: 51803, Context: "conn1", Message: "Slow query",
		Attr: map[string]interface{}{
			"ns":            "db.orders",
			"durationMillis": 150.0,
			"command": map[string]interface{}{
				"insert":     "orders",
				"txnNumber":  31.0,
				"autocommit": false,
			},
		},
	}

	acc := NewTransactionAccumulator()
	acc.Process(entry)

	r := acc.Result()
	if len(r.Transactions) != 1 {
		t.Fatalf("got %d transactions, want 1", len(r.Transactions))
	}
	if r.Transactions[0].TxnNumber != 31 {
		t.Errorf("txnNumber = %d, want 31", r.Transactions[0].TxnNumber)
	}
}

func TestTransactionAccumulator_SkipsNonTxn(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-04-18T12:00:00.000Z")
	entry := parser.LogEntry{
		Timestamp: ts, Severity: "I", Component: "COMMAND",
		ID: 51803, Context: "conn1", Message: "Slow query",
		Attr: map[string]interface{}{
			"ns":            "db.orders",
			"durationMillis": 150.0,
			"command":       map[string]interface{}{"find": "orders"},
		},
	}

	acc := NewTransactionAccumulator()
	acc.Process(entry)

	r := acc.Result()
	if len(r.Transactions) != 0 {
		t.Errorf("got %d transactions, want 0", len(r.Transactions))
	}
}
```

Create `analyzer/transaction.go`:

```go
package analyzer

import (
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type TransactionEvent struct {
	Timestamp        time.Time
	Namespace        string
	TxnNumber        int
	DurationMs       int
	ReadConcern      string
	TimeActiveMicros int
	TimeInactiveMicros int
	TerminationCause string
}

type TransactionResult struct {
	Transactions []TransactionEvent
}

type TransactionAccumulator struct {
	transactions []TransactionEvent
}

func NewTransactionAccumulator() *TransactionAccumulator {
	return &TransactionAccumulator{}
}

func (a *TransactionAccumulator) Process(entry parser.LogEntry) {
	cmd := entry.AttrMap("command")
	if cmd == nil {
		return
	}

	txnNum, ok := cmd["txnNumber"].(float64)
	if !ok {
		return
	}

	var readConcern string
	if rc, ok := cmd["readConcern"].(map[string]interface{}); ok {
		if level, ok := rc["level"].(string); ok {
			readConcern = level
		}
	}

	a.transactions = append(a.transactions, TransactionEvent{
		Timestamp:          entry.Timestamp,
		Namespace:          entry.AttrString("ns"),
		TxnNumber:          int(txnNum),
		DurationMs:         entry.AttrInt("durationMillis"),
		ReadConcern:        readConcern,
		TimeActiveMicros:   entry.AttrInt("timeActiveMicros"),
		TimeInactiveMicros: entry.AttrInt("timeInactiveMicros"),
		TerminationCause:   entry.AttrString("terminationCause"),
	})
}

func (a *TransactionAccumulator) Result() TransactionResult {
	return TransactionResult{Transactions: a.transactions}
}
```

- [ ] **Step 11: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestTransactionAccumulator -count=1
git add analyzer/transaction.go analyzer/transaction_test.go
git commit -m "feat: add transaction accumulator"
```

#### 9f: Errors Accumulator

- [ ] **Step 12: Write test + implement errors accumulator**

Create `analyzer/errors_test.go`:

```go
package analyzer

import "testing"

func TestErrorAccumulator_CollectsWarnings(t *testing.T) {
	acc := NewErrorAccumulator()

	acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "W", "QUERY", 23799, "Aggregate command executor error"))
	acc.Process(makeEntry("2026-04-18T12:00:01.000Z", "W", "QUERY", 23799, "Aggregate command executor error"))
	acc.Process(makeEntry("2026-04-18T12:00:02.000Z", "I", "NETWORK", 22943, "Connection accepted"))

	r := acc.Result()
	if len(r.Groups) != 1 {
		t.Fatalf("got %d groups, want 1 (skip info)", len(r.Groups))
	}
	if r.Groups[0].Count != 2 {
		t.Errorf("count = %d, want 2", r.Groups[0].Count)
	}
}

func TestErrorAccumulator_GroupsBySeverityComponentMsg(t *testing.T) {
	acc := NewErrorAccumulator()

	acc.Process(makeEntry("2026-04-18T12:00:00.000Z", "W", "QUERY", 1, "error A"))
	acc.Process(makeEntry("2026-04-18T12:00:01.000Z", "E", "QUERY", 2, "error A"))
	acc.Process(makeEntry("2026-04-18T12:00:02.000Z", "W", "STORAGE", 3, "error A"))

	r := acc.Result()
	if len(r.Groups) != 3 {
		t.Fatalf("got %d groups, want 3 (different severity/component combos)", len(r.Groups))
	}
}
```

Create `analyzer/errors.go`:

```go
package analyzer

import (
	"sort"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

type ErrorGroup struct {
	Severity   string
	Component  string
	Message    string
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	SampleAttr map[string]interface{}
}

type ErrorResult struct {
	Groups []ErrorGroup
}

type ErrorAccumulator struct {
	groups map[string]*ErrorGroup
}

func NewErrorAccumulator() *ErrorAccumulator {
	return &ErrorAccumulator{groups: make(map[string]*ErrorGroup)}
}

func (a *ErrorAccumulator) Process(entry parser.LogEntry) {
	if entry.Severity != "E" && entry.Severity != "W" && entry.Severity != "F" {
		return
	}

	key := entry.Severity + "|" + entry.Component + "|" + entry.Message
	g, ok := a.groups[key]
	if !ok {
		g = &ErrorGroup{
			Severity:  entry.Severity,
			Component: entry.Component,
			Message:   entry.Message,
			FirstSeen: entry.Timestamp,
		}
		a.groups[key] = g
	}
	g.Count++
	g.LastSeen = entry.Timestamp
	if g.SampleAttr == nil && entry.Attr != nil {
		g.SampleAttr = entry.Attr
	}
}

func (a *ErrorAccumulator) Result() ErrorResult {
	groups := make([]ErrorGroup, 0, len(a.groups))
	for _, g := range a.groups {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})
	return ErrorResult{Groups: groups}
}
```

- [ ] **Step 13: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -run TestErrorAccumulator -count=1
git add analyzer/errors.go analyzer/errors_test.go
git commit -m "feat: add error/warning accumulator with severity/component/msg grouping"
```

- [ ] **Step 14: Verify all analyzer tests pass together**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./analyzer/ -v -count=1
```

Expected: all tests in the analyzer package PASS. The `analyzer.go` orchestrator should now compile since all accumulator types are defined.

---

### Task 10: JSON Output Formatter

**Files:**
- Create: `report/json.go`
- Create: `report/json_test.go`

- [ ] **Step 1: Write failing test**

Create `report/json_test.go`:

```go
package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
)

func TestWriteJSON_ValidOutput(t *testing.T) {
	results := analyzer.Results{
		General: analyzer.GeneralResult{
			TotalLines:      100,
			StartTime:       time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC),
			EndTime:         time.Date(2026, 4, 18, 16, 0, 0, 0, time.UTC),
			SeverityCounts:  map[string]int{"I": 95, "W": 5},
			ComponentCounts: map[string]int{"NETWORK": 80, "COMMAND": 20},
			TopMessages:     []analyzer.MessageCount{{Message: "Connection accepted", Count: 50}},
		},
		SlowQueries: analyzer.SlowQueryResult{
			Groups: []analyzer.SlowQueryGroup{
				{Namespace: "db.test", CommandName: "find", Pattern: `{"x":1}`, Count: 3, MinMs: 100, MaxMs: 300, MeanMs: 200, P95Ms: 290, SumMs: 600},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, results)
	if err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if _, ok := parsed["general"]; !ok {
		t.Error("missing 'general' key in JSON output")
	}
	if _, ok := parsed["slowQueries"]; !ok {
		t.Error("missing 'slowQueries' key in JSON output")
	}
}
```

- [ ] **Step 2: Implement JSON formatter**

Create `report/json.go`:

```go
package report

import (
	"encoding/json"
	"io"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
)

type jsonOutput struct {
	General      analyzer.GeneralResult      `json:"general"`
	SlowQueries  analyzer.SlowQueryResult    `json:"slowQueries"`
	TableScans   analyzer.TableScanResult    `json:"tableScans"`
	Connections  analyzer.ConnectionResult   `json:"connections"`
	Clients      analyzer.ClientResult       `json:"clients"`
	Distinct     analyzer.DistinctResult     `json:"distinct"`
	RSState      analyzer.RSStateResult      `json:"rsState"`
	Storage      analyzer.StorageResult      `json:"storage"`
	Transactions analyzer.TransactionResult  `json:"transactions"`
	Errors       analyzer.ErrorResult        `json:"errors"`
}

func WriteJSON(w io.Writer, results analyzer.Results) error {
	out := jsonOutput{
		General:      results.General,
		SlowQueries:  results.SlowQueries,
		TableScans:   results.TableScans,
		Connections:  results.Connections,
		Clients:      results.Clients,
		Distinct:     results.Distinct,
		RSState:      results.RSState,
		Storage:      results.Storage,
		Transactions: results.Transactions,
		Errors:       results.Errors,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
```

- [ ] **Step 3: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./report/ -v -run TestWriteJSON -count=1
git add report/json.go report/json_test.go
git commit -m "feat: add JSON output formatter"
```

---

### Task 11: HTML Report with Plotly.js

**Files:**
- Create: `report/template.html`
- Create: `report/html.go`
- Create: `report/html_test.go`

This is the largest single task. The HTML template includes all 15 report sections with embedded Plotly.js.

- [ ] **Step 1: Write failing test for HTML generation**

Create `report/html_test.go`:

```go
package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
)

func TestWriteHTML_ContainsAllSections(t *testing.T) {
	results := analyzer.Results{
		General: analyzer.GeneralResult{
			TotalLines:      100,
			StartTime:       time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC),
			EndTime:         time.Date(2026, 4, 18, 16, 0, 0, 0, time.UTC),
			SeverityCounts:  map[string]int{"I": 95, "W": 5},
			ComponentCounts: map[string]int{"NETWORK": 80, "COMMAND": 20},
			TopMessages:     []analyzer.MessageCount{{Message: "Connection accepted", Count: 50}},
		},
		SlowQueries: analyzer.SlowQueryResult{
			Groups: []analyzer.SlowQueryGroup{
				{Namespace: "db.test", CommandName: "find", Pattern: `{"x":1}`, Count: 3, MinMs: 100, MaxMs: 300, MeanMs: 200, P95Ms: 290, SumMs: 600},
			},
			Timeline: []analyzer.TimelineBucket{
				{Time: time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC), Count: 3},
			},
		},
		Connections: analyzer.ConnectionResult{
			TotalOpened:     50,
			TotalClosed:     48,
			PeakConnections: 100,
		},
		Errors: analyzer.ErrorResult{
			Groups: []analyzer.ErrorGroup{
				{Severity: "W", Component: "QUERY", Message: "test error", Count: 5,
					FirstSeen: time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC),
					LastSeen:  time.Date(2026, 4, 18, 16, 0, 0, 0, time.UTC)},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteHTML(&buf, results, "")
	if err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}

	html := buf.String()

	checks := []string{
		"<!DOCTYPE html>",
		"plotly",
		"Executive Summary",
		"Slow Query Analysis",
		"Connection Analysis",
		"Errors &amp; Warnings",
		"db.test",
	}
	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Errorf("HTML missing %q", check)
		}
	}
}
```

- [ ] **Step 2: Create the HTML template**

Create `report/template.html`. This is a large file — the template uses Go's `html/template` syntax with Plotly.js CDN link (self-contained by embedding the full Plotly.js is optional; CDN is simpler for the initial version and can be switched to embedded later).

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MLA Report — {{.General.StartTime.Format "2006-01-02"}}</title>
<!-- Plotly.js will be embedded at build time via a separate step. For development, use CDN: -->
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<!-- TODO for Task 15: download plotly.min.js to report/plotly.min.js and embed via //go:embed -->
<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff; --red: #f85149; --green: #3fb950; --yellow: #d29922; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; padding: 20px; }
.container { max-width: 1400px; margin: 0 auto; }
h1 { font-size: 1.8em; margin-bottom: 8px; }
h2 { font-size: 1.3em; margin: 30px 0 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
.header-meta { color: var(--muted); font-size: 0.9em; margin-bottom: 20px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.card-value { font-size: 1.8em; font-weight: 600; }
.card-label { color: var(--muted); font-size: 0.85em; }
.chart-container { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 20px; }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9em; }
th { background: #1c2128; cursor: pointer; user-select: none; }
th:hover { background: #22272e; }
tr:hover { background: #1c2128; }
.severity-W { color: var(--yellow); }
.severity-E { color: var(--red); }
.severity-F { color: var(--red); font-weight: bold; }
.alert-row { background: rgba(248, 81, 73, 0.1); }
.expandable { cursor: pointer; }
.expanded-content { display: none; background: #1c2128; padding: 12px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; word-break: break-all; }
.expanded-content.show { display: table-row; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; background: var(--border); margin: 2px; }
.ai-section { background: var(--card); border: 2px solid var(--accent); border-radius: 8px; padding: 20px; margin-top: 20px; }
</style>
</head>
<body>
<div class="container">

<h1>MongoDB Log Analysis Report</h1>
<div class="header-meta">
{{.General.StartTime.Format "2006-01-02 15:04:05 UTC"}} — {{.General.EndTime.Format "2006-01-02 15:04:05 UTC"}}
({{printf "%.1f" .DurationHours}} hours)
</div>

<h2>Executive Summary</h2>
<div class="cards">
<div class="card"><div class="card-value">{{.General.TotalLines | comma}}</div><div class="card-label">Total Log Lines</div></div>
<div class="card"><div class="card-value">{{len .SlowQueries.Groups}}</div><div class="card-label">Slow Query Patterns</div></div>
<div class="card"><div class="card-value">{{.SlowQueryCount}}</div><div class="card-label">Slow Queries</div></div>
<div class="card"><div class="card-value">{{len .TableScans.Scans}}</div><div class="card-label">Table Scans</div></div>
<div class="card"><div class="card-value">{{.Connections.PeakConnections | comma}}</div><div class="card-label">Peak Connections</div></div>
<div class="card"><div class="card-value">{{.ErrorCount}}</div><div class="card-label">Errors &amp; Warnings</div></div>
</div>

<h2>Operations Timeline</h2>
<div class="chart-container"><div id="timeline-chart"></div></div>

<h2>Slow Query Analysis</h2>
{{if .SlowQueries.Groups}}
<table id="slow-query-table">
<thead><tr>
<th onclick="sortTable('slow-query-table',0)">Namespace</th>
<th onclick="sortTable('slow-query-table',1)">Command</th>
<th onclick="sortTable('slow-query-table',2)">Pattern</th>
<th onclick="sortTable('slow-query-table',3)">Count</th>
<th onclick="sortTable('slow-query-table',4)">Min (ms)</th>
<th onclick="sortTable('slow-query-table',5)">Max (ms)</th>
<th onclick="sortTable('slow-query-table',6)">Mean (ms)</th>
<th onclick="sortTable('slow-query-table',7)">P95 (ms)</th>
<th onclick="sortTable('slow-query-table',8)">Sum (ms)</th>
</tr></thead>
<tbody>
{{range .SlowQueries.Groups}}
<tr class="expandable" onclick="toggleRow(this)">
<td>{{.Namespace}}</td>
<td>{{.CommandName}}</td>
<td><code>{{.Pattern}}</code></td>
<td>{{.Count}}</td>
<td>{{.MinMs}}</td>
<td>{{.MaxMs}}</td>
<td>{{.MeanMs}}</td>
<td>{{.P95Ms}}</td>
<td>{{.SumMs}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No slow queries detected.</p>
{{end}}

<h2>Slow Query Scatter</h2>
<div class="chart-container"><div id="scatter-chart"></div></div>

<h2>Duration Breakdown (Top 20)</h2>
<div class="chart-container"><div id="breakdown-chart"></div></div>

{{if .TableScans.Scans}}
<h2>Table Scan Alerts</h2>
<table>
<thead><tr><th>Time</th><th>Namespace</th><th>Plan</th><th>Docs Examined</th><th>Returned</th><th>Duration (ms)</th></tr></thead>
<tbody>
{{range .TableScans.Scans}}
<tr class="alert-row">
<td>{{.Timestamp.Format "15:04:05"}}</td>
<td>{{.Namespace}}</td>
<td>{{.PlanSummary}}</td>
<td>{{.DocsExamined | comma}}</td>
<td>{{.NReturned | comma}}</td>
<td>{{.DurationMs}}</td>
</tr>
{{end}}
</tbody>
</table>
{{end}}

<h2>Connection Analysis</h2>
<div class="cards">
<div class="card"><div class="card-value">{{.Connections.TotalOpened | comma}}</div><div class="card-label">Opened</div></div>
<div class="card"><div class="card-value">{{.Connections.TotalClosed | comma}}</div><div class="card-label">Closed</div></div>
<div class="card"><div class="card-value">{{.Connections.PeakConnections | comma}}</div><div class="card-label">Peak</div></div>
</div>
<div class="chart-container"><div id="conn-chart"></div></div>

{{if .Connections.ByIP}}
<h3>Top Client IPs</h3>
<table>
<thead><tr><th>IP</th><th>Connections</th></tr></thead>
<tbody>{{range .TopIPs}}<tr><td>{{.IP}}</td><td>{{.Count | comma}}</td></tr>{{end}}</tbody>
</table>
{{end}}

{{if .Clients.Groups}}
<h2>Client Summary</h2>
<table>
<thead><tr><th>Driver</th><th>Version</th><th>App Name</th><th>Connections</th></tr></thead>
<tbody>{{range .Clients.Groups}}<tr><td>{{.DriverName}}</td><td>{{.DriverVersion}}</td><td>{{.AppName}}</td><td>{{.Count}}</td></tr>{{end}}</tbody>
</table>
{{end}}

<h2>Distinct Log Patterns</h2>
<table id="distinct-table">
<thead><tr>
<th onclick="sortTable('distinct-table',0)">Message</th>
<th onclick="sortTable('distinct-table',1)">Count</th>
<th onclick="sortTable('distinct-table',2)">First Seen</th>
<th onclick="sortTable('distinct-table',3)">Last Seen</th>
</tr></thead>
<tbody>{{range .Distinct.Patterns}}<tr><td>{{.Message}}</td><td>{{.Count | comma}}</td><td>{{.FirstSeen.Format "15:04:05"}}</td><td>{{.LastSeen.Format "15:04:05"}}</td></tr>{{end}}</tbody>
</table>

{{if .RSState.Transitions}}
<h2>Replica Set State</h2>
<table>
<thead><tr><th>Time</th><th>Message</th></tr></thead>
<tbody>{{range .RSState.Transitions}}<tr><td>{{.Timestamp.Format "15:04:05"}}</td><td>{{.Message}}</td></tr>{{end}}</tbody>
</table>
{{end}}

{{if .Storage.ByNamespace}}
<h2>Storage Stats</h2>
<table>
<thead><tr><th>Namespace</th><th>Bytes Read</th><th>Bytes Written</th><th>Read Time (μs)</th><th>Write Time (μs)</th><th>Ops</th></tr></thead>
<tbody>{{range .Storage.ByNamespace}}<tr><td>{{.Namespace}}</td><td>{{.TotalBytesRead | comma}}</td><td>{{.TotalBytesWritten | comma}}</td><td>{{.TotalTimeReadUs | comma}}</td><td>{{.TotalTimeWriteUs | comma}}</td><td>{{.OpCount}}</td></tr>{{end}}</tbody>
</table>
{{end}}

{{if .Transactions.Transactions}}
<h2>Transactions</h2>
<table>
<thead><tr><th>Time</th><th>Namespace</th><th>Txn#</th><th>Duration (ms)</th></tr></thead>
<tbody>{{range .Transactions.Transactions}}<tr><td>{{.Timestamp.Format "15:04:05"}}</td><td>{{.Namespace}}</td><td>{{.TxnNumber}}</td><td>{{.DurationMs}}</td></tr>{{end}}</tbody>
</table>
{{end}}

{{if .Errors.Groups}}
<h2>Errors &amp; Warnings</h2>
<table>
<thead><tr><th>Severity</th><th>Component</th><th>Message</th><th>Count</th><th>First</th><th>Last</th></tr></thead>
<tbody>{{range .Errors.Groups}}<tr><td class="severity-{{.Severity}}">{{.Severity}}</td><td>{{.Component}}</td><td>{{.Message}}</td><td>{{.Count}}</td><td>{{.FirstSeen.Format "15:04:05"}}</td><td>{{.LastSeen.Format "15:04:05"}}</td></tr>{{end}}</tbody>
</table>
{{end}}

{{if .AIAnalysis}}
<h2>AI Analysis</h2>
<div class="ai-section">{{.AIAnalysis}}</div>
{{end}}

</div>

<script>
var timelineData = {{.TimelineJSON}};
var scatterData = {{.ScatterJSON}};
var breakdownData = {{.BreakdownJSON}};
var connData = {{.ConnTimelineJSON}};

if (timelineData && timelineData.length > 0) {
  Plotly.newPlot('timeline-chart', timelineData, {
    title: 'Events per Minute by Component',
    xaxis: {title: 'Time', type: 'date'},
    yaxis: {title: 'Events'},
    barmode: 'stack',
    plot_bgcolor: '#161b22', paper_bgcolor: '#161b22',
    font: {color: '#e6edf3'}
  }, {responsive: true});
}

if (scatterData && scatterData.length > 0) {
  Plotly.newPlot('scatter-chart', scatterData, {
    title: 'Slow Query Duration Over Time',
    xaxis: {title: 'Time', type: 'date'},
    yaxis: {title: 'Duration (ms)', type: 'log'},
    plot_bgcolor: '#161b22', paper_bgcolor: '#161b22',
    font: {color: '#e6edf3'}
  }, {responsive: true});
}

if (breakdownData && breakdownData.length > 0) {
  Plotly.newPlot('breakdown-chart', breakdownData, {
    title: 'Duration Breakdown by Query Pattern',
    barmode: 'stack',
    xaxis: {title: 'Time (ms)'},
    yaxis: {automargin: true},
    plot_bgcolor: '#161b22', paper_bgcolor: '#161b22',
    font: {color: '#e6edf3'}
  }, {responsive: true});
}

if (connData && connData.length > 0) {
  Plotly.newPlot('conn-chart', connData, {
    title: 'Connection Count Over Time',
    xaxis: {title: 'Time', type: 'date'},
    yaxis: {title: 'Connections'},
    plot_bgcolor: '#161b22', paper_bgcolor: '#161b22',
    font: {color: '#e6edf3'}
  }, {responsive: true});
}

function sortTable(tableId, col) {
  var table = document.getElementById(tableId);
  var rows = Array.from(table.tBodies[0].rows);
  var asc = table.dataset.sortCol == col && table.dataset.sortDir != 'asc';
  rows.sort(function(a, b) {
    var av = a.cells[col].textContent.replace(/,/g,'');
    var bv = b.cells[col].textContent.replace(/,/g,'');
    var an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(function(r) { table.tBodies[0].appendChild(r); });
  table.dataset.sortCol = col;
  table.dataset.sortDir = asc ? 'asc' : 'desc';
}

function toggleRow(row) {
  var next = row.nextElementSibling;
  if (next && next.classList.contains('expanded-content')) {
    next.classList.toggle('show');
  }
}

// Link time axes: zooming timeline updates scatter and conn charts
var timelineEl = document.getElementById('timeline-chart');
if (timelineEl) {
  timelineEl.on('plotly_relayout', function(ed) {
    if (ed['xaxis.range[0]'] && ed['xaxis.range[1]']) {
      var update = {'xaxis.range': [ed['xaxis.range[0]'], ed['xaxis.range[1]']]};
      Plotly.relayout('scatter-chart', update);
      Plotly.relayout('conn-chart', update);
    }
    if (ed['xaxis.autorange']) {
      Plotly.relayout('scatter-chart', {'xaxis.autorange': true});
      Plotly.relayout('conn-chart', {'xaxis.autorange': true});
    }
  });
}

// Dark/light theme toggle
var toggle = document.createElement('button');
toggle.textContent = 'Toggle Theme';
toggle.style.cssText = 'position:fixed;top:10px;right:10px;z-index:1000;padding:6px 12px;border-radius:6px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;font-size:0.8em;';
document.body.appendChild(toggle);
toggle.onclick = function() {
  var r = document.documentElement.style;
  var isDark = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() === '#0d1117';
  if (isDark) {
    r.setProperty('--bg','#ffffff'); r.setProperty('--card','#f6f8fa'); r.setProperty('--border','#d0d7de');
    r.setProperty('--text','#1f2328'); r.setProperty('--muted','#656d76');
    var lightLayout = {plot_bgcolor:'#f6f8fa', paper_bgcolor:'#f6f8fa', font:{color:'#1f2328'}};
    ['timeline-chart','scatter-chart','breakdown-chart','conn-chart'].forEach(function(id){Plotly.relayout(id,lightLayout);});
  } else {
    r.setProperty('--bg','#0d1117'); r.setProperty('--card','#161b22'); r.setProperty('--border','#30363d');
    r.setProperty('--text','#e6edf3'); r.setProperty('--muted','#8b949e');
    var darkLayout = {plot_bgcolor:'#161b22', paper_bgcolor:'#161b22', font:{color:'#e6edf3'}};
    ['timeline-chart','scatter-chart','breakdown-chart','conn-chart'].forEach(function(id){Plotly.relayout(id,darkLayout);});
  }
};
</script>
</body>
</html>
```

- [ ] **Step 3: Implement HTML generator**

Create `report/html.go`:

```go
package report

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
)

//go:embed template.html
var templateFS embed.FS

type htmlData struct {
	analyzer.Results
	AIAnalysis      template.HTML
	DurationHours   float64
	SlowQueryCount  int
	ErrorCount      int
	TopIPs          []analyzer.IPStats
	TimelineJSON    template.JS
	ScatterJSON     template.JS
	BreakdownJSON   template.JS
	ConnTimelineJSON template.JS
}

func comma(v interface{}) string {
	switch n := v.(type) {
	case int:
		return commaInt(int64(n))
	case int64:
		return commaInt(n)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func commaInt(n int64) string {
	if n < 0 {
		return "-" + commaInt(-n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

func WriteHTML(w io.Writer, results analyzer.Results, aiAnalysis string) error {
	tmplContent, err := templateFS.ReadFile("template.html")
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}

	funcMap := template.FuncMap{
		"comma": comma,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var slowCount int
	for _, g := range results.SlowQueries.Groups {
		slowCount += g.Count
	}

	var errorCount int
	for _, g := range results.Errors.Groups {
		errorCount += g.Count
	}

	topIPs := results.Connections.ByIP
	if len(topIPs) > 20 {
		topIPs = topIPs[:20]
	}

	duration := results.General.EndTime.Sub(results.General.StartTime)

	data := htmlData{
		Results:        results,
		AIAnalysis:     template.HTML(aiAnalysis),
		DurationHours:  duration.Hours(),
		SlowQueryCount: slowCount,
		ErrorCount:     errorCount,
		TopIPs:         topIPs,
		TimelineJSON:   template.JS(buildTimelineJSON(results)),
		ScatterJSON:    template.JS(buildScatterJSON(results)),
		BreakdownJSON:  template.JS(buildBreakdownJSON(results)),
		ConnTimelineJSON: template.JS(buildConnTimelineJSON(results)),
	}

	return tmpl.Execute(w, data)
}

func buildTimelineJSON(r analyzer.Results) string {
	if len(r.SlowQueries.Timeline) == 0 {
		return "[]"
	}

	times := make([]string, len(r.SlowQueries.Timeline))
	counts := make([]int, len(r.SlowQueries.Timeline))
	for i, b := range r.SlowQueries.Timeline {
		times[i] = b.Time.Format(time.RFC3339)
		counts[i] = b.Count
	}

	trace := map[string]interface{}{
		"x":    times,
		"y":    counts,
		"type": "bar",
		"name": "Slow Queries",
		"marker": map[string]string{"color": "#58a6ff"},
	}
	b, _ := json.Marshal([]interface{}{trace})
	return string(b)
}

func buildScatterJSON(r analyzer.Results) string {
	if len(r.SlowQueries.Groups) == 0 {
		return "[]"
	}

	var traces []interface{}
	for _, g := range r.SlowQueries.Groups {
		if g.Count == 0 {
			continue
		}
		trace := map[string]interface{}{
			"x":    []string{},
			"y":    []int{g.MeanMs},
			"mode": "markers",
			"type": "scattergl",
			"name": g.Namespace + " " + g.CommandName,
			"marker": map[string]interface{}{"size": 8},
		}
		traces = append(traces, trace)
	}

	b, _ := json.Marshal(traces)
	return string(b)
}

func buildBreakdownJSON(r analyzer.Results) string {
	groups := r.SlowQueries.Groups
	if len(groups) == 0 {
		return "[]"
	}
	if len(groups) > 20 {
		groups = groups[:20]
	}

	labels := make([]string, len(groups))
	cpuMs := make([]float64, len(groups))
	wcMs := make([]float64, len(groups))
	storMs := make([]float64, len(groups))
	otherMs := make([]float64, len(groups))

	for i, g := range groups {
		labels[i] = g.Namespace + " " + g.CommandName
		cpu := float64(g.MeanCPUNanos) / 1e6
		wc := float64(g.MeanWriteConcernMs)
		stor := float64(g.MeanStorageWaitUs) / 1e3
		other := float64(g.MeanMs) - cpu - wc - stor
		if other < 0 {
			other = 0
		}
		cpuMs[i] = cpu
		wcMs[i] = wc
		storMs[i] = stor
		otherMs[i] = other
	}

	traces := []interface{}{
		map[string]interface{}{"y": labels, "x": cpuMs, "name": "CPU", "type": "bar", "orientation": "h", "marker": map[string]string{"color": "#58a6ff"}},
		map[string]interface{}{"y": labels, "x": wcMs, "name": "Write Concern Wait", "type": "bar", "orientation": "h", "marker": map[string]string{"color": "#d29922"}},
		map[string]interface{}{"y": labels, "x": storMs, "name": "Storage Wait", "type": "bar", "orientation": "h", "marker": map[string]string{"color": "#f85149"}},
		map[string]interface{}{"y": labels, "x": otherMs, "name": "Other", "type": "bar", "orientation": "h", "marker": map[string]string{"color": "#8b949e"}},
	}
	b, _ := json.Marshal(traces)
	return string(b)
}

func buildConnTimelineJSON(r analyzer.Results) string {
	if len(r.Connections.Timeline) == 0 {
		return "[]"
	}

	times := make([]string, len(r.Connections.Timeline))
	counts := make([]int, len(r.Connections.Timeline))
	for i, b := range r.Connections.Timeline {
		times[i] = b.Time.Format(time.RFC3339)
		counts[i] = b.ConnectionCount
	}

	trace := map[string]interface{}{
		"x":    times,
		"y":    counts,
		"type": "scatter",
		"mode": "lines",
		"name": "Connection Count",
		"line": map[string]string{"color": "#3fb950"},
		"fill": "tozeroy",
	}
	b, _ := json.Marshal([]interface{}{trace})
	return string(b)
}
```

- [ ] **Step 4: Run test, verify pass, commit**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./report/ -v -count=1
git add report/template.html report/html.go report/html_test.go
git commit -m "feat: add HTML report generator with Plotly.js charts and dark theme"
```

---

### Task 12: AI Integration

**Files:**
- Create: `report/ai.go`

- [ ] **Step 1: Implement AI synthesis module**

Create `report/ai.go`:

```go
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
)

func RunAISynthesis(results analyzer.Results, aiCmd string, repoPath string) (string, error) {
	metricsJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal metrics: %w", err)
	}

	var codeContext string
	if repoPath != "" {
		codeContext = scanRepoForContext(results, repoPath)
	}

	duration := results.General.EndTime.Sub(results.General.StartTime)

	prompt := fmt.Sprintf(`You are analyzing MongoDB server logs for a production database. Here are the analysis results from a %s window.

## Key Metrics
%s

%s

## Instructions
Provide:
1. Executive summary (3-5 sentences covering overall health)
2. Top issues ranked by severity and impact:
   - For each: root cause analysis, supporting evidence from metrics,
     and a specific actionable fix (index creation commands, code changes,
     config recommendations)
3. Quick wins (can fix in <1 hour) vs. longer-term improvements
4. Any concerning patterns or trends

Format as HTML (no wrapping <html>/<body> tags, just content with <h3>, <p>, <ul>, <code> tags).`,
		duration.Round(time.Minute).String(),
		string(metricsJSON),
		codeContext,
	)

	parts := strings.Fields(aiCmd)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty ai-cmd")
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ai command %q failed: %w\nstderr: %s", aiCmd, err, stderr.String())
	}

	return stdout.String(), nil
}

func scanRepoForContext(results analyzer.Results, repoPath string) string {
	namespaces := make(map[string]bool)
	for _, g := range results.SlowQueries.Groups {
		parts := strings.SplitN(g.Namespace, ".", 2)
		if len(parts) == 2 {
			namespaces[parts[1]] = true
		}
	}

	if len(namespaces) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## Application Code Context\n")

	for collection := range namespaces {
		matches := grepRepo(repoPath, collection)
		if len(matches) > 0 {
			sb.WriteString(fmt.Sprintf("\n### Collection: %s\n", collection))
			for _, m := range matches {
				if len(m) > 500 {
					m = m[:500] + "..."
				}
				sb.WriteString(m + "\n")
			}
		}
	}

	return sb.String()
}

func grepRepo(repoPath, pattern string) []string {
	cmd := exec.Command("grep", "-rn", "--include=*.js", "--include=*.ts", "--include=*.go", "--include=*.py", "-l", pattern, repoPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()

	var results []string
	for _, file := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if file == "" {
			continue
		}
		rel, _ := filepath.Rel(repoPath, file)
		if rel == "" {
			rel = file
		}
		results = append(results, rel)
		if len(results) >= 5 {
			break
		}
	}
	return results
}
```


- [ ] **Step 2: Commit**

```bash
git add report/ai.go
git commit -m "feat: add AI synthesis module with repo scanning and configurable AI command"
```

---

### Task 13: CLI Entry Point (main.go)

**Files:**
- Create: `main.go`

- [ ] **Step 1: Implement CLI entry point**

Create `main.go`:

```go
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
	"github.com/Seitk/mongodb-logs-analyzer/report"
)

func main() {
	format := flag.String("format", "html", "Output format: html, json")
	output := flag.String("o", "", "Output file path (default: {logname}_report.html)")
	output2 := flag.String("output", "", "Output file path (alias for -o)")
	ai := flag.Bool("ai", false, "Enable AI synthesis")
	repo := flag.String("repo", "", "Path to application repo for code correlation")
	aiCmd := flag.String("ai-cmd", "claude -p", "AI command (reads stdin, writes stdout)")
	slowMS := flag.Int("slow", 100, "Slow query threshold in milliseconds")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: mla [flags] <logfile>\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	logFile := flag.Arg(0)

	outFile := *output
	if outFile == "" {
		outFile = *output2
	}

	a := analyzer.New(*slowMS)
	fmt.Fprintf(os.Stderr, "Analyzing %s...\n", logFile)

	results, err := a.Run(logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Processed %d lines (%d slow queries, %d connections)\n",
		results.General.TotalLines,
		slowQueryCount(results),
		results.Connections.TotalOpened,
	)

	switch *format {
	case "json":
		w := os.Stdout
		if outFile != "" {
			f, err := os.Create(outFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			w = f
		}
		if err := report.WriteJSON(w, results); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}

	case "html":
		if outFile == "" {
			base := logFile
			if len(base) > 4 && base[len(base)-4:] == ".log" {
				base = base[:len(base)-4]
			}
			outFile = base + "_report.html"
		}

		var aiAnalysis string
		if *ai {
			fmt.Fprintf(os.Stderr, "Running AI synthesis with %q...\n", *aiCmd)
			aiAnalysis, err = report.RunAISynthesis(results, *aiCmd, *repo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "AI synthesis failed: %v\n", err)
			}
		}

		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		if err := report.WriteHTML(f, results, aiAnalysis); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Report written to %s\n", outFile)

	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", *format)
		os.Exit(1)
	}
}

func slowQueryCount(r analyzer.Results) int {
	var count int
	for _, g := range r.SlowQueries.Groups {
		count += g.Count
	}
	return count
}
```

- [ ] **Step 2: Build and verify it compiles**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go build -o mla .
```

Expected: compiles with no errors, produces `mla` binary.

- [ ] **Step 3: Commit**

```bash
git add main.go
git commit -m "feat: add CLI entry point with flag parsing and output routing"
```

---

### Task 14: Integration Test Against Real Log File

**Files:**
- Create: `main_test.go`

- [ ] **Step 1: Write integration test**

Create `main_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
	"github.com/Seitk/mongodb-logs-analyzer/report"
)

const realLogFile = "sample-shard-00-02_2026-04-18T12_37_07_2026-04-18T16_37_07_MONGODB.log"

func TestIntegration_RealLogFile(t *testing.T) {
	if _, err := os.Stat(realLogFile); os.IsNotExist(err) {
		t.Skip("Real log file not present, skipping integration test")
	}

	a := analyzer.New(100)
	results, err := a.Run(realLogFile)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if results.General.TotalLines != 956777 {
		t.Errorf("TotalLines = %d, want 956777", results.General.TotalLines)
	}

	var slowCount int
	for _, g := range results.SlowQueries.Groups {
		slowCount += g.Count
	}
	if slowCount != 239 {
		t.Errorf("slow query count = %d, want 239", slowCount)
	}

	if results.Connections.TotalOpened != 155318 {
		t.Errorf("connections opened = %d, want 155318", results.Connections.TotalOpened)
	}
	if results.Connections.TotalClosed != 149377 {
		t.Errorf("connections closed = %d, want 149377", results.Connections.TotalClosed)
	}

	if results.General.SeverityCounts["W"] != 11 {
		t.Errorf("warnings = %d, want 11", results.General.SeverityCounts["W"])
	}

	// Verify JSON output is valid
	jsonBuf := new(bytes.Buffer)
	if err := report.WriteJSON(jsonBuf, results); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}

	// Verify HTML output is valid
	htmlBuf := new(bytes.Buffer)
	if err := report.WriteHTML(htmlBuf, results, ""); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	if htmlBuf.Len() < 1000 {
		t.Errorf("HTML output seems too short: %d bytes", htmlBuf.Len())
	}
}

func BenchmarkParsing(b *testing.B) {
	if _, err := os.Stat(realLogFile); os.IsNotExist(err) {
		b.Skip("Real log file not present")
	}

	for i := 0; i < b.N; i++ {
		a := analyzer.New(100)
		_, err := a.Run(realLogFile)
		if err != nil {
			b.Fatal(err)
		}
	}
}
```


- [ ] **Step 2: Run integration test**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test -v -run TestIntegration_RealLogFile -timeout 120s -count=1
```

Expected: PASS with all verification targets matching.

- [ ] **Step 3: Run benchmark**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test -bench BenchmarkParsing -benchtime 1x -timeout 120s
```

Expected: completes in under 10 seconds.

- [ ] **Step 4: Run the full tool and open the report**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && ./mla "sample-shard-00-02_2026-04-18T12_37_07_2026-04-18T16_37_07_MONGODB.log" && open "sample-shard-00-02_2026-04-18T12_37_07_2026-04-18T16_37_07_MONGODB_report.html"
```

Expected: HTML report opens in browser with all sections populated and interactive Plotly.js charts.

- [ ] **Step 5: Commit**

```bash
git add main_test.go
git commit -m "test: add integration test and benchmark against real 348MB log file"
```

---

### Task 15: Embed Plotly.js + Final Polish

- [ ] **Step 0: Download and embed Plotly.js for self-contained HTML**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer
curl -sL https://cdn.plot.ly/plotly-2.35.2.min.js -o report/plotly.min.js
```

Then update `report/html.go` to embed it:

```go
//go:embed plotly.min.js
var plotlyJS []byte
```

And update `report/template.html` to use the embedded content:

Replace the CDN `<script src="..."></script>` with:
```html
<script>{{.PlotlyJS}}</script>
```

Add `PlotlyJS template.JS` to the `htmlData` struct and set it:
```go
PlotlyJS: template.JS(plotlyJS),
```

- [ ] **Step 1: Update .gitignore**

Add to `.gitignore`:

```
*.log
mla
*_report.html
```

- [ ] **Step 2: Run all tests one final time**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go test ./... -v -timeout 120s -count=1
```

Expected: all tests PASS across all packages.

- [ ] **Step 3: Build final binary**

```bash
cd /Users/philip/Development/mongodb-logs-analyzer && go build -o mla . && ./mla --help
```

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: update gitignore for build artifacts and reports"
```

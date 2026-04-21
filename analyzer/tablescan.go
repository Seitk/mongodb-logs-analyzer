package analyzer

import (
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

// TableScanEntry represents a detected table scan / collection scan.
type TableScanEntry struct {
	Timestamp    time.Time
	Namespace    string
	PlanSummary  string
	DocsExamined int
	KeysExamined int
	NReturned    int
	DurationMs   int
	Command      map[string]interface{}
}

// TableScanResult holds all detected table scans.
type TableScanResult struct {
	Scans []TableScanEntry
}

// TableScanAccumulator detects table scans in slow query entries.
type TableScanAccumulator struct {
	scans []TableScanEntry
}

// NewTableScanAccumulator creates a new TableScanAccumulator.
func NewTableScanAccumulator() *TableScanAccumulator {
	return &TableScanAccumulator{}
}

// Process checks if a slow query entry (ID 51803) is a table scan.
func (t *TableScanAccumulator) Process(entry parser.LogEntry) {
	planSummary := entry.AttrString("planSummary")
	docsExamined := entry.AttrInt("docsExamined")
	nReturned := entry.AttrInt("nreturned")

	isCollScan := strings.Contains(planSummary, "COLLSCAN")
	isHighRatio := docsExamined > 10000 && nReturned > 0 && docsExamined/nReturned > 100

	if !isCollScan && !isHighRatio {
		return
	}

	t.scans = append(t.scans, TableScanEntry{
		Timestamp:    entry.Timestamp,
		Namespace:    entry.AttrString("ns"),
		PlanSummary:  planSummary,
		DocsExamined: docsExamined,
		KeysExamined: entry.AttrInt("keysExamined"),
		NReturned:    nReturned,
		DurationMs:   entry.AttrInt("durationMillis"),
		Command:      entry.AttrMap("command"),
	})
}

// Result returns the table scan results.
func (t *TableScanAccumulator) Result() TableScanResult {
	return TableScanResult{Scans: t.scans}
}

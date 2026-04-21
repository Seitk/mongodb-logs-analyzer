package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/mla/analyzer"
)

func sampleResults() analyzer.Results {
	return analyzer.Results{
		General: analyzer.GeneralResult{
			TotalLines:      50000,
			StartTime:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			EndTime:         time.Date(2024, 1, 1, 4, 0, 0, 0, time.UTC),
			SeverityCounts:  map[string]int{"I": 45000, "W": 4000, "E": 1000},
			ComponentCounts: map[string]int{"COMMAND": 30000, "NETWORK": 15000},
			TopMessages:     []analyzer.MessageCount{{Message: "Slow query", Count: 500}},
			Host:            "prod-mongo-01",
			ReplicaSet:      "rs0",
			Version:         "7.0.4",
			Binary:          "mongod",
			StorageEngine:   "wiredTiger",
		},
		SlowQueries: analyzer.SlowQueryResult{
			Groups: []analyzer.SlowQueryGroup{
				{
					Namespace:          "mydb.users",
					Type:               "command",
					CmdName:            "find",
					Pattern:            `{"email":1}`,
					Count:              150,
					MinMs:              102,
					MaxMs:              5432,
					MeanMs:             340,
					P95Ms:              2100,
					SumMs:              51000,
					MeanCPUNanos:       50000000,
					MeanWriteConcernMs: 0,
					MeanStorageWaitUs:  12000,
					MeanQueueUs:        500,
				},
				{
					Namespace: "mydb.orders",
					Type:      "command",
					CmdName:   "aggregate",
					Pattern:   `[{"$match":{"status":1}},{"$group":{"_id":1}}]`,
					Count:     80,
					MinMs:     200,
					MaxMs:     8000,
					MeanMs:    1200,
					P95Ms:     6000,
					SumMs:     96000,
				},
			},
			Timeline: []analyzer.SlowQueryTimelineBucket{
				{Minute: time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC), Count: 5},
				{Minute: time.Date(2024, 1, 1, 2, 0, 0, 0, time.UTC), Count: 12},
				{Minute: time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC), Count: 3},
			},
		},
		TableScans: analyzer.TableScanResult{
			Scans: []analyzer.TableScanEntry{
				{
					Timestamp:    time.Date(2024, 1, 1, 1, 30, 0, 0, time.UTC),
					Namespace:    "mydb.logs",
					PlanSummary:  "COLLSCAN",
					DocsExamined: 500000,
					NReturned:    10,
					DurationMs:   3200,
				},
			},
		},
		Connections: analyzer.ConnectionResult{
			TotalOpened:     2500,
			TotalClosed:     2400,
			PeakConnections: 150,
			ByIP: []analyzer.IPStats{
				{IP: "10.0.1.1", Count: 500},
				{IP: "10.0.1.2", Count: 300},
			},
			Timeline: []analyzer.ConnTimelineBucket{
				{Minute: time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC), Opened: 10, Closed: 5, ConnectionCount: 50},
			},
		},
		Clients: analyzer.ClientResult{
			Groups: []analyzer.ClientGroup{
				{
					DriverName:    "nodejs",
					DriverVersion: "5.0.0",
					AppName:       "myapp",
					Count:         100,
					UniqueIPs:     map[string]struct{}{"10.0.1.1": {}},
				},
			},
		},
		Distinct: analyzer.DistinctResult{
			Groups: []analyzer.DistinctGroup{
				{
					Message:   "Slow query",
					Count:     500,
					FirstSeen: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
					LastSeen:  time.Date(2024, 1, 1, 4, 0, 0, 0, time.UTC),
				},
			},
		},
		RSState: analyzer.RSStateResult{
			Events: []analyzer.RSStateEvent{
				{
					Timestamp: time.Date(2024, 1, 1, 2, 0, 0, 0, time.UTC),
					Message:   "Member state transition: SECONDARY -> PRIMARY",
				},
			},
		},
		Storage: analyzer.StorageResult{
			Namespaces: []analyzer.StorageNamespace{
				{
					Namespace:         "mydb.users",
					TotalBytesRead:    1024 * 1024 * 500,
					TotalBytesWritten: 1024 * 1024 * 100,
					TotalTimeReadUs:   5000000,
					TotalTimeWriteUs:  1000000,
					OpCount:           150,
					MeanBytesRead:     1024 * 1024 * 3,
					MeanBytesWritten:  1024 * 700,
				},
			},
		},
		Transactions: analyzer.TransactionResult{
			Transactions: []analyzer.TransactionEntry{
				{
					Timestamp:  time.Date(2024, 1, 1, 1, 15, 0, 0, time.UTC),
					Namespace:  "mydb.orders",
					TxnNumber:  42,
					DurationMs: 1500,
					ReadConcern: "majority",
				},
			},
		},
		Errors: analyzer.ErrorResult{
			Groups: []analyzer.ErrorGroup{
				{
					Severity:  "E",
					Component: "NETWORK",
					Message:   "Connection refused to 10.0.2.1:27017",
					Count:     25,
					FirstSeen: time.Date(2024, 1, 1, 0, 30, 0, 0, time.UTC),
					LastSeen:  time.Date(2024, 1, 1, 3, 45, 0, 0, time.UTC),
				},
				{
					Severity:  "W",
					Component: "COMMAND",
					Message:   "Slow operation detected",
					Count:     200,
					FirstSeen: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
					LastSeen:  time.Date(2024, 1, 1, 4, 0, 0, 0, time.UTC),
				},
			},
		},
	}
}

func TestWriteHTML_ContainsExpectedSections(t *testing.T) {
	results := sampleResults()

	var buf bytes.Buffer
	err := WriteHTML(&buf, results, "")
	if err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}

	html := buf.String()

	expectedStrings := []string{
		"<!DOCTYPE html>",
		"plotly",
		"Executive Summary",
		"Slow Query Analysis",
		"Table Scan Alerts",
		"Connection Analysis",
		"Client Summary",
		"Distinct Log Patterns",
		"Replica Set State",
		"Storage I/O",
		"Transactions",
		"Errors &amp; Warnings",
		// Data values
		"50,000",
		"prod-mongo-01",
		"rs0",
		"7.0.4",
		"mydb.users",
		"mydb.orders",
		"COLLSCAN",
		"10.0.1.1",
		"nodejs",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(html, s) {
			t.Errorf("HTML output missing expected string: %q", s)
		}
	}
}

func TestWriteHTML_WithAIAnalysis(t *testing.T) {
	results := sampleResults()
	aiHTML := "<h3>Key Findings</h3><p>The database shows signs of stress.</p>"

	var buf bytes.Buffer
	err := WriteHTML(&buf, results, aiHTML)
	if err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "AI Analysis") {
		t.Error("HTML output missing AI Analysis section header")
	}
	if !strings.Contains(html, "Key Findings") {
		t.Error("HTML output missing AI analysis content")
	}
}

func TestWriteHTML_EmptyResults(t *testing.T) {
	results := analyzer.Results{
		General: analyzer.GeneralResult{
			SeverityCounts:  map[string]int{},
			ComponentCounts: map[string]int{},
		},
	}

	var buf bytes.Buffer
	err := WriteHTML(&buf, results, "")
	if err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
	if !strings.Contains(html, "Executive Summary") {
		t.Error("HTML output missing Executive Summary for empty results")
	}
}

func TestCommaFormat(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{0, "0"},
		{100, "100"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{int64(9999999), "9,999,999"},
		{-1234, "-1,234"},
	}

	for _, tt := range tests {
		result := commaFormat(tt.input)
		if result != tt.expected {
			t.Errorf("commaFormat(%v) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024 * 5, "5.0 MB"},
		{1024 * 1024 * 1024 * 2, "2.0 GB"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.input)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a long string that needs truncating", 20, "this is a long st..."},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

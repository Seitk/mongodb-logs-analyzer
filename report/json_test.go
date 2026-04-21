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
			TotalLines:      1000,
			StartTime:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			EndTime:         time.Date(2024, 1, 1, 4, 0, 0, 0, time.UTC),
			SeverityCounts:  map[string]int{"I": 900, "W": 80, "E": 20},
			ComponentCounts: map[string]int{"COMMAND": 500, "NETWORK": 300},
			TopMessages:     []analyzer.MessageCount{{Message: "Slow query", Count: 50}},
			Host:            "mongo-host-1",
			ReplicaSet:      "rs0",
			Version:         "7.0.0",
			Binary:          "mongod",
			StorageEngine:   "wiredTiger",
		},
		SlowQueries: analyzer.SlowQueryResult{
			Groups: []analyzer.SlowQueryGroup{
				{
					Namespace: "db.collection",
					Type:      "command",
					CmdName:   "find",
					Pattern:   `{"field":1}`,
					Count:     10,
					MinMs:     100,
					MaxMs:     500,
					MeanMs:    200,
					P95Ms:     450,
					SumMs:     2000,
				},
			},
			Timeline: []analyzer.SlowQueryTimelineBucket{
				{Minute: time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC), Count: 5},
			},
		},
		Connections: analyzer.ConnectionResult{
			TotalOpened:     100,
			TotalClosed:     90,
			PeakConnections: 50,
		},
		Errors: analyzer.ErrorResult{
			Groups: []analyzer.ErrorGroup{
				{
					Severity:  "E",
					Component: "NETWORK",
					Message:   "Connection refused",
					Count:     5,
					FirstSeen: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
					LastSeen:  time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC),
				},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, results)
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify expected top-level keys
	expectedKeys := []string{
		"general", "slowQueries", "tableScans", "connections",
		"clients", "distinct", "rsState", "storage",
		"transactions", "errors",
	}
	for _, key := range expectedKeys {
		if _, ok := parsed[key]; !ok {
			t.Errorf("Missing expected key %q in JSON output", key)
		}
	}

	// Verify some values
	general := parsed["general"].(map[string]interface{})
	if int(general["TotalLines"].(float64)) != 1000 {
		t.Errorf("Expected TotalLines=1000, got %v", general["TotalLines"])
	}
	if general["Host"] != "mongo-host-1" {
		t.Errorf("Expected Host=mongo-host-1, got %v", general["Host"])
	}
}

func TestWriteJSON_EmptyResults(t *testing.T) {
	results := analyzer.Results{
		General: analyzer.GeneralResult{
			SeverityCounts:  map[string]int{},
			ComponentCounts: map[string]int{},
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, results)
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}
}

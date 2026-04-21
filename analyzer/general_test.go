package analyzer

import (
	"testing"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

// makeEntry is a test helper for building LogEntry values.
func makeEntry(ts string, severity, component string, id int, msg string) parser.LogEntry {
	t, _ := time.Parse(time.RFC3339Nano, ts)
	return parser.LogEntry{Timestamp: t, Severity: severity, Component: component, ID: id, Context: "test", Message: msg}
}

func TestGeneralAccumulator_BasicStats(t *testing.T) {
	acc := NewGeneralAccumulator()

	entries := []parser.LogEntry{
		makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 1, "listening"),
		makeEntry("2024-01-01T00:01:00Z", "I", "COMMAND", 2, "slow query"),
		makeEntry("2024-01-01T00:02:00Z", "W", "STORAGE", 3, "disk warning"),
		makeEntry("2024-01-01T00:03:00Z", "E", "NETWORK", 4, "connection error"),
		makeEntry("2024-01-01T00:04:00Z", "I", "COMMAND", 5, "slow query"),
	}

	for _, e := range entries {
		acc.Process(e)
	}

	result := acc.Result()

	if result.TotalLines != 5 {
		t.Errorf("TotalLines = %d, want 5", result.TotalLines)
	}

	wantStart, _ := time.Parse(time.RFC3339Nano, "2024-01-01T00:00:00Z")
	wantEnd, _ := time.Parse(time.RFC3339Nano, "2024-01-01T00:04:00Z")

	if !result.StartTime.Equal(wantStart) {
		t.Errorf("StartTime = %v, want %v", result.StartTime, wantStart)
	}
	if !result.EndTime.Equal(wantEnd) {
		t.Errorf("EndTime = %v, want %v", result.EndTime, wantEnd)
	}

	if result.SeverityCounts["I"] != 3 {
		t.Errorf("SeverityCounts[I] = %d, want 3", result.SeverityCounts["I"])
	}
	if result.SeverityCounts["W"] != 1 {
		t.Errorf("SeverityCounts[W] = %d, want 1", result.SeverityCounts["W"])
	}
	if result.SeverityCounts["E"] != 1 {
		t.Errorf("SeverityCounts[E] = %d, want 1", result.SeverityCounts["E"])
	}

	if result.ComponentCounts["NETWORK"] != 2 {
		t.Errorf("ComponentCounts[NETWORK] = %d, want 2", result.ComponentCounts["NETWORK"])
	}
	if result.ComponentCounts["COMMAND"] != 2 {
		t.Errorf("ComponentCounts[COMMAND] = %d, want 2", result.ComponentCounts["COMMAND"])
	}
	if result.ComponentCounts["STORAGE"] != 1 {
		t.Errorf("ComponentCounts[STORAGE] = %d, want 1", result.ComponentCounts["STORAGE"])
	}
}

func TestGeneralAccumulator_MessageFrequency(t *testing.T) {
	acc := NewGeneralAccumulator()

	for i := 0; i < 10; i++ {
		acc.Process(makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 1, "top message"))
	}
	for i := 0; i < 5; i++ {
		acc.Process(makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 1, "second message"))
	}
	acc.Process(makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 1, "rare message"))

	result := acc.Result()

	if len(result.TopMessages) == 0 {
		t.Fatal("TopMessages is empty")
	}
	if result.TopMessages[0].Message != "top message" {
		t.Errorf("TopMessages[0].Message = %q, want %q", result.TopMessages[0].Message, "top message")
	}
	if result.TopMessages[0].Count != 10 {
		t.Errorf("TopMessages[0].Count = %d, want 10", result.TopMessages[0].Count)
	}
}

func TestGeneralAccumulator_ServerInfo(t *testing.T) {
	acc := NewGeneralAccumulator()

	e1 := makeEntry("2024-01-01T00:00:00Z", "I", "CONTROL", 23403, "server info")
	e1.Attr = map[string]interface{}{"host": "mongo-primary.example.com"}
	acc.Process(e1)

	e2 := makeEntry("2024-01-01T00:00:01Z", "I", "REPL", 21752, "replica set")
	e2.Attr = map[string]interface{}{"replSetName": "rs0"}
	acc.Process(e2)

	e3 := makeEntry("2024-01-01T00:00:02Z", "I", "CONTROL", 23299, "version")
	e3.Attr = map[string]interface{}{"version": "7.0.4"}
	acc.Process(e3)

	e4 := makeEntry("2024-01-01T00:00:03Z", "I", "CONTROL", 23400, "binary")
	e4.Attr = map[string]interface{}{"binary": "mongod"}
	acc.Process(e4)

	e5 := makeEntry("2024-01-01T00:00:04Z", "I", "STORAGE", 22315, "wiredtiger init")
	acc.Process(e5)

	result := acc.Result()

	if result.Host != "mongo-primary.example.com" {
		t.Errorf("Host = %q, want %q", result.Host, "mongo-primary.example.com")
	}
	if result.ReplicaSet != "rs0" {
		t.Errorf("ReplicaSet = %q, want %q", result.ReplicaSet, "rs0")
	}
	if result.Version != "7.0.4" {
		t.Errorf("Version = %q, want %q", result.Version, "7.0.4")
	}
	if result.Binary != "mongod" {
		t.Errorf("Binary = %q, want %q", result.Binary, "mongod")
	}
	if result.StorageEngine != "wiredTiger" {
		t.Errorf("StorageEngine = %q, want %q", result.StorageEngine, "wiredTiger")
	}
}

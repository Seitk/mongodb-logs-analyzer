package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestScanner_BasicLines(t *testing.T) {
	content := `{"t":{"$date":"2026-04-18T12:36:15.017+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,"ctx":"listener","msg":"Connection accepted","attr":{}}
{"t":{"$date":"2026-04-18T12:36:15.018+00:00"},"s":"I",  "c":"NETWORK",  "id":22944,"ctx":"conn1","msg":"Connection ended","attr":{}}
{"t":{"$date":"2026-04-18T12:36:15.019+00:00"},"s":"I",  "c":"COMMAND",  "id":51803,"ctx":"conn2","msg":"Slow query","attr":{}}
`
	path := writeTempFile(t, content)

	var entries []LogEntry
	err := ScanFile(path, func(e LogEntry) {
		entries = append(entries, e)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Message != "Connection accepted" {
		t.Errorf("entries[0].Message = %q, want %q", entries[0].Message, "Connection accepted")
	}
	if entries[2].Message != "Slow query" {
		t.Errorf("entries[2].Message = %q, want %q", entries[2].Message, "Slow query")
	}
}

func TestScanner_SkipsMalformedLines(t *testing.T) {
	content := `{"t":{"$date":"2026-04-18T12:36:15.017+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,"ctx":"listener","msg":"Line 1","attr":{}}
this is not valid json
{"t":{"$date":"2026-04-18T12:36:15.019+00:00"},"s":"I",  "c":"COMMAND",  "id":51803,"ctx":"conn2","msg":"Line 3","attr":{}}
also invalid {{{
{"t":{"$date":"2026-04-18T12:36:15.020+00:00"},"s":"I",  "c":"COMMAND",  "id":51803,"ctx":"conn3","msg":"Line 5","attr":{}}
`
	path := writeTempFile(t, content)

	var entries []LogEntry
	err := ScanFile(path, func(e LogEntry) {
		entries = append(entries, e)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3 (should skip malformed)", len(entries))
	}
	if entries[0].Message != "Line 1" {
		t.Errorf("entries[0].Message = %q, want %q", entries[0].Message, "Line 1")
	}
	if entries[1].Message != "Line 3" {
		t.Errorf("entries[1].Message = %q, want %q", entries[1].Message, "Line 3")
	}
	if entries[2].Message != "Line 5" {
		t.Errorf("entries[2].Message = %q, want %q", entries[2].Message, "Line 5")
	}
}

func TestScanner_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")

	var count int
	err := ScanFile(path, func(e LogEntry) {
		count++
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("got %d entries, want 0", count)
	}
}

func TestScanner_FileNotFound(t *testing.T) {
	err := ScanFile("/nonexistent/path/to/file.log", func(e LogEntry) {
		t.Fatal("callback should not be called for nonexistent file")
	})
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

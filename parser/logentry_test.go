package parser

import (
	"testing"
	"time"
)

func TestParseLogEntry_SlowQuery(t *testing.T) {
	line := []byte(`{"t":{"$date":"2026-04-18T12:50:44.119+00:00"},"s":"I",  "c":"COMMAND",  "id":51803,   "ctx":"conn56141","msg":"Slow query","attr":{"type":"command","ns":"config.$cmd","durationMillis":101,"command":{"update":"availability","updates":[{"q":{"_id":"000000000000000000000001"},"u":{"$inc":{"seq":1}}}]}}}`)

	entry, err := ParseLogEntry(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry.Severity != "I" {
		t.Errorf("severity = %q, want %q", entry.Severity, "I")
	}
	if entry.Component != "COMMAND" {
		t.Errorf("component = %q, want %q", entry.Component, "COMMAND")
	}
	if entry.ID != 51803 {
		t.Errorf("id = %d, want %d", entry.ID, 51803)
	}
	if entry.Context != "conn56141" {
		t.Errorf("context = %q, want %q", entry.Context, "conn56141")
	}
	if entry.Message != "Slow query" {
		t.Errorf("message = %q, want %q", entry.Message, "Slow query")
	}
	if entry.AttrString("type") != "command" {
		t.Errorf("attr type = %q, want %q", entry.AttrString("type"), "command")
	}
	if entry.AttrString("ns") != "config.$cmd" {
		t.Errorf("attr ns = %q, want %q", entry.AttrString("ns"), "config.$cmd")
	}
	if entry.AttrInt("durationMillis") != 101 {
		t.Errorf("attr durationMillis = %d, want %d", entry.AttrInt("durationMillis"), 101)
	}
	cmd := entry.AttrMap("command")
	if cmd == nil {
		t.Fatal("attr command is nil")
	}
	if cmd["update"] != "availability" {
		t.Errorf("command.update = %v, want %q", cmd["update"], "availability")
	}
}

func TestParseLogEntry_ConnectionAccepted(t *testing.T) {
	line := []byte(`{"t":{"$date":"2026-04-18T12:36:15.018+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,   "ctx":"listener","msg":"Connection accepted","attr":{"remote":"127.0.0.1:57380","connectionId":55617,"connectionCount":15524}}`)

	entry, err := ParseLogEntry(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry.Component != "NETWORK" {
		t.Errorf("component = %q, want %q", entry.Component, "NETWORK")
	}
	if entry.ID != 22943 {
		t.Errorf("id = %d, want %d", entry.ID, 22943)
	}
	if entry.Context != "listener" {
		t.Errorf("context = %q, want %q", entry.Context, "listener")
	}
	if entry.Message != "Connection accepted" {
		t.Errorf("message = %q, want %q", entry.Message, "Connection accepted")
	}
	if entry.AttrString("remote") != "127.0.0.1:57380" {
		t.Errorf("attr remote = %q, want %q", entry.AttrString("remote"), "127.0.0.1:57380")
	}
	if entry.AttrInt("connectionId") != 55617 {
		t.Errorf("attr connectionId = %d, want %d", entry.AttrInt("connectionId"), 55617)
	}
}

func TestParseLogEntry_TimestampParsing(t *testing.T) {
	line := []byte(`{"t":{"$date":"2026-04-18T12:36:15.574+00:00"},"s":"I",  "c":"WTCHKPT",  "id":22430,   "ctx":"Checkpointer","msg":"WiredTiger message","attr":{}}`)

	entry, err := ParseLogEntry(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := time.Date(2026, 4, 18, 12, 36, 15, 574000000, time.UTC)
	if !entry.Timestamp.Equal(expected) {
		t.Errorf("timestamp = %v, want %v", entry.Timestamp, expected)
	}
}

func TestParseLogEntry_SeverityWhitespace(t *testing.T) {
	// MongoDB logs pad component to 8 chars with trailing spaces
	line := []byte(`{"t":{"$date":"2026-04-18T12:36:15.017+00:00"},"s":"I",  "c":"-",        "id":20883,   "ctx":"conn55592","msg":"Interrupted operation","attr":{}}`)

	entry, err := ParseLogEntry(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The severity field in the JSON has no whitespace issue, but component does
	if entry.Severity != "I" {
		t.Errorf("severity = %q, want %q", entry.Severity, "I")
	}
	if entry.Component != "-" {
		t.Errorf("component = %q, want %q (whitespace not trimmed?)", entry.Component, "-")
	}
}

func TestParseLogEntry_InvalidJSON(t *testing.T) {
	line := []byte(`this is not JSON at all`)

	_, err := ParseLogEntry(line)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

package parser

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LogEntry represents a parsed MongoDB LOGV2 JSON log line.
type LogEntry struct {
	Timestamp time.Time
	Severity  string // F, E, W, I, D1-D5
	Component string // NETWORK, COMMAND, ACCESS, etc.
	ID        int
	Context   string
	Message   string
	Attr      map[string]interface{}
}

// rawLogEntry is the intermediate structure for JSON unmarshaling.
type rawLogEntry struct {
	T   map[string]string      `json:"t"`
	S   string                 `json:"s"`
	C   string                 `json:"c"`
	ID  int                    `json:"id"`
	Ctx string                 `json:"ctx"`
	Msg string                 `json:"msg"`
	Attr map[string]interface{} `json:"attr"`
}

// ParseLogEntry unmarshals a MongoDB LOGV2 JSON line into a LogEntry.
func ParseLogEntry(line []byte) (LogEntry, error) {
	var raw rawLogEntry
	if err := json.Unmarshal(line, &raw); err != nil {
		return LogEntry{}, fmt.Errorf("parse log entry: %w", err)
	}

	dateStr, ok := raw.T["$date"]
	if !ok {
		return LogEntry{}, fmt.Errorf("parse log entry: missing $date in timestamp")
	}

	ts, err := time.Parse(time.RFC3339Nano, dateStr)
	if err != nil {
		// Try alternate format with milliseconds
		ts, err = time.Parse("2006-01-02T15:04:05.000-07:00", dateStr)
		if err != nil {
			return LogEntry{}, fmt.Errorf("parse log entry: invalid timestamp %q: %w", dateStr, err)
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

// AttrString returns the string value of the given attribute key, or empty string if not found or not a string.
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
		return ""
	}
	return s
}

// AttrInt returns the integer value of the given attribute key.
// JSON numbers are decoded as float64, so this converts accordingly.
// Returns 0 if not found or not a number.
func (e *LogEntry) AttrInt(key string) int {
	if e.Attr == nil {
		return 0
	}
	v, ok := e.Attr[key]
	if !ok {
		return 0
	}
	f, ok := v.(float64)
	if !ok {
		return 0
	}
	return int(f)
}

// AttrFloat returns the float64 value of the given attribute key.
// Returns 0 if not found or not a number.
func (e *LogEntry) AttrFloat(key string) float64 {
	if e.Attr == nil {
		return 0
	}
	v, ok := e.Attr[key]
	if !ok {
		return 0
	}
	f, ok := v.(float64)
	if !ok {
		return 0
	}
	return f
}

// AttrMap returns the nested map value of the given attribute key.
// Returns nil if not found or not a map.
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

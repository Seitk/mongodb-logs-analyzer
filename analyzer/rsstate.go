package analyzer

import (
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

// RSStateEvent represents a replica set state change event.
type RSStateEvent struct {
	Timestamp time.Time
	Message   string
}

// RSStateResult holds all replica set state change events.
type RSStateResult struct {
	Events []RSStateEvent
}

// RSStateAccumulator detects replica set state changes.
type RSStateAccumulator struct {
	events []RSStateEvent
}

// NewRSStateAccumulator creates a new RSStateAccumulator.
func NewRSStateAccumulator() *RSStateAccumulator {
	return &RSStateAccumulator{}
}

// Process checks if an entry is a replica set state change.
func (r *RSStateAccumulator) Process(entry parser.LogEntry) {
	if entry.Component != "REPL" {
		return
	}

	lower := strings.ToLower(entry.Message)
	if strings.Contains(lower, "transition") || strings.Contains(lower, "state change") {
		r.events = append(r.events, RSStateEvent{
			Timestamp: entry.Timestamp,
			Message:   entry.Message,
		})
	}
}

// Result returns the replica set state change events.
func (r *RSStateAccumulator) Result() RSStateResult {
	return RSStateResult{Events: r.events}
}

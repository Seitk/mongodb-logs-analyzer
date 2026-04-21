package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/internal/parser"
)

// ErrorGroup holds stats for a group of similar errors/warnings.
type ErrorGroup struct {
	Severity   string
	Component  string
	Message    string
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	SampleAttr map[string]interface{}
}

// ErrorResult holds all error analysis results.
type ErrorResult struct {
	Groups []ErrorGroup
}

// ErrorAccumulator groups errors and warnings.
type ErrorAccumulator struct {
	groups map[string]*ErrorGroup
}

// NewErrorAccumulator creates a new ErrorAccumulator.
func NewErrorAccumulator() *ErrorAccumulator {
	return &ErrorAccumulator{
		groups: make(map[string]*ErrorGroup),
	}
}

// Process processes a log entry, collecting errors, warnings, and fatals.
func (e *ErrorAccumulator) Process(entry parser.LogEntry) {
	switch entry.Severity {
	case "E", "W", "F":
		// proceed
	default:
		return
	}

	key := fmt.Sprintf("%s|%s|%s", entry.Severity, entry.Component, entry.Message)

	grp, exists := e.groups[key]
	if !exists {
		grp = &ErrorGroup{
			Severity:  entry.Severity,
			Component: entry.Component,
			Message:   entry.Message,
			FirstSeen: entry.Timestamp,
			LastSeen:  entry.Timestamp,
		}
		if entry.Attr != nil {
			grp.SampleAttr = entry.Attr
		}
		e.groups[key] = grp
	}

	grp.Count++
	if entry.Timestamp.Before(grp.FirstSeen) {
		grp.FirstSeen = entry.Timestamp
	}
	if entry.Timestamp.After(grp.LastSeen) {
		grp.LastSeen = entry.Timestamp
	}
	if grp.SampleAttr == nil && entry.Attr != nil {
		grp.SampleAttr = entry.Attr
	}
}

// Result returns the error analysis results sorted by count descending.
func (e *ErrorAccumulator) Result() ErrorResult {
	groups := make([]ErrorGroup, 0, len(e.groups))
	for _, grp := range e.groups {
		groups = append(groups, *grp)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})
	return ErrorResult{Groups: groups}
}

package analyzer

import (
	"sort"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/internal/parser"
)

// DistinctGroup holds stats for a distinct message pattern.
type DistinctGroup struct {
	Message    string
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	SampleAttr map[string]interface{}
}

// DistinctResult holds all distinct message results.
type DistinctResult struct {
	Groups []DistinctGroup
}

// DistinctAccumulator groups log entries by distinct message.
type DistinctAccumulator struct {
	groups map[string]*DistinctGroup
}

// NewDistinctAccumulator creates a new DistinctAccumulator.
func NewDistinctAccumulator() *DistinctAccumulator {
	return &DistinctAccumulator{
		groups: make(map[string]*DistinctGroup),
	}
}

// Process processes a log entry for distinct message tracking.
func (d *DistinctAccumulator) Process(entry parser.LogEntry) {
	grp, exists := d.groups[entry.Message]
	if !exists {
		grp = &DistinctGroup{
			Message:   entry.Message,
			FirstSeen: entry.Timestamp,
			LastSeen:  entry.Timestamp,
		}
		if entry.Attr != nil {
			grp.SampleAttr = entry.Attr
		}
		d.groups[entry.Message] = grp
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

// Result returns the distinct message results sorted by count descending.
func (d *DistinctAccumulator) Result() DistinctResult {
	groups := make([]DistinctGroup, 0, len(d.groups))
	for _, grp := range d.groups {
		groups = append(groups, *grp)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})
	return DistinctResult{Groups: groups}
}

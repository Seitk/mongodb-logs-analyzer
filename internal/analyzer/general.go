package analyzer

import (
	"sort"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/internal/parser"
)

// MessageCount holds a message string and its occurrence count.
type MessageCount struct {
	Message string
	Count   int
}

// GeneralResult holds overall log statistics.
type GeneralResult struct {
	TotalLines      int
	StartTime       time.Time
	EndTime         time.Time
	SeverityCounts  map[string]int
	ComponentCounts map[string]int
	TopMessages     []MessageCount
	Host            string
	ReplicaSet      string
	Version         string
	Binary          string
	StorageEngine   string
}

// GeneralAccumulator tracks general log statistics.
type GeneralAccumulator struct {
	totalLines      int
	startTime       time.Time
	endTime         time.Time
	severityCounts  map[string]int
	componentCounts map[string]int
	messageCounts   map[string]int
	host            string
	replicaSet      string
	version         string
	binary          string
	storageEngine   string
}

// NewGeneralAccumulator creates a new GeneralAccumulator.
func NewGeneralAccumulator() *GeneralAccumulator {
	return &GeneralAccumulator{
		severityCounts:  make(map[string]int),
		componentCounts: make(map[string]int),
		messageCounts:   make(map[string]int),
	}
}

// Process processes a single log entry.
func (g *GeneralAccumulator) Process(entry parser.LogEntry) {
	g.totalLines++

	if g.startTime.IsZero() || entry.Timestamp.Before(g.startTime) {
		g.startTime = entry.Timestamp
	}
	if entry.Timestamp.After(g.endTime) {
		g.endTime = entry.Timestamp
	}

	g.severityCounts[entry.Severity]++
	g.componentCounts[entry.Component]++
	g.messageCounts[entry.Message]++

	// Detect server info
	switch entry.ID {
	case 23403:
		if h := entry.AttrString("host"); h != "" {
			g.host = h
		}
	case 21752:
		if rs := entry.AttrString("replSetName"); rs != "" {
			g.replicaSet = rs
		}
	case 23299:
		if v := entry.AttrString("version"); v != "" {
			g.version = v
		}
	case 23400:
		if b := entry.AttrString("binary"); b != "" {
			g.binary = b
		}
	case 22315:
		g.storageEngine = "wiredTiger"
	}
}

// Result returns the collected general statistics.
func (g *GeneralAccumulator) Result() GeneralResult {
	// Build top messages sorted by count descending
	msgs := make([]MessageCount, 0, len(g.messageCounts))
	for msg, count := range g.messageCounts {
		msgs = append(msgs, MessageCount{Message: msg, Count: count})
	}
	sort.Slice(msgs, func(i, j int) bool {
		return msgs[i].Count > msgs[j].Count
	})

	limit := 20
	if len(msgs) < limit {
		limit = len(msgs)
	}

	return GeneralResult{
		TotalLines:      g.totalLines,
		StartTime:       g.startTime,
		EndTime:         g.endTime,
		SeverityCounts:  g.severityCounts,
		ComponentCounts: g.componentCounts,
		TopMessages:     msgs[:limit],
		Host:            g.host,
		ReplicaSet:      g.replicaSet,
		Version:         g.version,
		Binary:          g.binary,
		StorageEngine:   g.storageEngine,
	}
}

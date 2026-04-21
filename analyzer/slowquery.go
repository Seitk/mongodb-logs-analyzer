package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/anthropics/mla/parser"
)

// percentile computes the p-th percentile from a sorted slice of ints.
// p should be between 0 and 100. The slice must be sorted ascending.
func percentile(sorted []int, p float64) int {
	if len(sorted) == 0 {
		return 0
	}
	rank := p / 100.0 * float64(len(sorted)-1)
	idx := int(rank)
	if idx >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	return sorted[idx]
}

// SlowQueryGroup holds aggregated stats for a group of similar slow queries.
type SlowQueryGroup struct {
	Namespace          string
	Type               string
	CmdName            string
	Pattern            string
	AllowDiskUse       bool
	Count              int
	MinMs              int
	MaxMs              int
	MeanMs             int
	P95Ms              int
	SumMs              int
	MeanCPUNanos       int64
	MeanWriteConcernMs int
	MeanStorageWaitUs  int
	MeanQueueUs        int
	SampleCommand      map[string]interface{}
	durations          []int
	sumCPUNanos        int64
	sumWriteConcernMs  int
	sumStorageWaitUs   int
	sumQueueUs         int
}

// SlowQueryTimelineBucket holds slow query count per minute bucket.
type SlowQueryTimelineBucket struct {
	Minute time.Time
	Count  int
}

// SlowQueryResult holds all slow query analysis results.
type SlowQueryResult struct {
	Groups   []SlowQueryGroup
	Timeline []SlowQueryTimelineBucket
}

// SlowQueryAccumulator groups and aggregates slow queries.
type SlowQueryAccumulator struct {
	groups   map[string]*SlowQueryGroup
	timeline map[time.Time]int
}

// NewSlowQueryAccumulator creates a new SlowQueryAccumulator.
func NewSlowQueryAccumulator() *SlowQueryAccumulator {
	return &SlowQueryAccumulator{
		groups:   make(map[string]*SlowQueryGroup),
		timeline: make(map[time.Time]int),
	}
}

// Process processes a slow query entry (ID 51803, already filtered by duration threshold).
func (s *SlowQueryAccumulator) Process(entry parser.LogEntry) {
	dur := entry.AttrInt("durationMillis")
	ns := entry.AttrString("ns")
	typ := entry.AttrString("type")

	cmd := entry.AttrMap("command")
	cmdName, pattern := parser.ExtractPattern(cmd)

	// Check allowDiskUse
	allowDisk := false
	if cmd != nil {
		if v, ok := cmd["allowDiskUse"]; ok {
			if b, ok := v.(bool); ok && b {
				allowDisk = true
			}
		}
	}

	// Build grouping key
	key := fmt.Sprintf("%s|%s|%s|%s", ns, typ, cmdName, pattern)
	if allowDisk {
		key += "|disk"
	}

	grp, exists := s.groups[key]
	if !exists {
		grp = &SlowQueryGroup{
			Namespace:    ns,
			Type:         typ,
			CmdName:      cmdName,
			Pattern:      pattern,
			AllowDiskUse: allowDisk,
			MinMs:        dur,
			MaxMs:        dur,
		}
		s.groups[key] = grp
	}

	grp.Count++
	grp.SumMs += dur
	grp.durations = append(grp.durations, dur)

	if dur < grp.MinMs {
		grp.MinMs = dur
	}
	if dur > grp.MaxMs {
		grp.MaxMs = dur
	}

	if grp.SampleCommand == nil {
		grp.SampleCommand = cmd
	}

	// Duration breakdown
	grp.sumCPUNanos += int64(entry.AttrInt("cpuNanos"))

	grp.sumWriteConcernMs += entry.AttrInt("waitForWriteConcernDurationMillis")

	// storage.timeWaitingMicros.storageEngineMicros
	if storageMap := entry.AttrMap("storage"); storageMap != nil {
		if twMap, ok := storageMap["timeWaitingMicros"].(map[string]interface{}); ok {
			if v, ok := twMap["storageEngineMicros"].(float64); ok {
				grp.sumStorageWaitUs += int(v)
			}
		}
	}

	// queues.execution.totalTimeQueuedMicros
	if queuesMap := entry.AttrMap("queues"); queuesMap != nil {
		if execMap, ok := queuesMap["execution"].(map[string]interface{}); ok {
			if v, ok := execMap["totalTimeQueuedMicros"].(float64); ok {
				grp.sumQueueUs += int(v)
			}
		}
	}

	// Timeline: 1-minute bucket
	minute := entry.Timestamp.Truncate(time.Minute)
	s.timeline[minute]++
}

// Result returns the slow query analysis results.
func (s *SlowQueryAccumulator) Result() SlowQueryResult {
	groups := make([]SlowQueryGroup, 0, len(s.groups))
	for _, grp := range s.groups {
		// Compute mean and p95
		if grp.Count > 0 {
			grp.MeanMs = grp.SumMs / grp.Count
			grp.MeanCPUNanos = grp.sumCPUNanos / int64(grp.Count)
			grp.MeanWriteConcernMs = grp.sumWriteConcernMs / grp.Count
			grp.MeanStorageWaitUs = grp.sumStorageWaitUs / grp.Count
			grp.MeanQueueUs = grp.sumQueueUs / grp.Count
		}
		sort.Ints(grp.durations)
		grp.P95Ms = percentile(grp.durations, 95)
		groups = append(groups, *grp)
	}

	// Sort groups by SumMs descending
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].SumMs > groups[j].SumMs
	})

	// Build timeline
	timeline := make([]SlowQueryTimelineBucket, 0, len(s.timeline))
	for minute, count := range s.timeline {
		timeline = append(timeline, SlowQueryTimelineBucket{Minute: minute, Count: count})
	}
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Minute.Before(timeline[j].Minute)
	})

	return SlowQueryResult{
		Groups:   groups,
		Timeline: timeline,
	}
}

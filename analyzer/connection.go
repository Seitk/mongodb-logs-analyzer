package analyzer

import (
	"sort"
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

// IPStats holds connection stats for a single IP address.
type IPStats struct {
	IP    string
	Count int
}

// ConnTimelineBucket holds connection activity per minute.
type ConnTimelineBucket struct {
	Minute          time.Time
	Opened          int
	Closed          int
	ConnectionCount int
}

// TLSStats holds TLS handshake statistics.
type TLSStats struct {
	Count  int
	MinMs  float64
	MaxMs  float64
	MeanMs float64
	P95Ms  float64
}

// ConnDurationStats holds connection duration statistics.
type ConnDurationStats struct {
	Count  int
	MinMs  float64
	MaxMs  float64
	MeanMs float64
	P95Ms  float64
}

// ConnectionResult holds all connection analysis results.
type ConnectionResult struct {
	TotalOpened     int
	TotalClosed     int
	PeakConnections int
	ByIP            []IPStats
	Timeline        []ConnTimelineBucket
	TLS             TLSStats
	Duration        ConnDurationStats
}

// ConnectionAccumulator tracks connection metrics.
type ConnectionAccumulator struct {
	totalOpened     int
	totalClosed     int
	currentConns    int
	peakConns       int
	ipCounts        map[string]int
	timeline        map[time.Time]*ConnTimelineBucket
	tlsDurations    []float64
	openConns       map[int]time.Time
	connDurations   []float64
}

// NewConnectionAccumulator creates a new ConnectionAccumulator.
func NewConnectionAccumulator() *ConnectionAccumulator {
	return &ConnectionAccumulator{
		ipCounts:  make(map[string]int),
		timeline:  make(map[time.Time]*ConnTimelineBucket),
		openConns: make(map[int]time.Time),
	}
}

// extractIP strips the port from a remote address string (splits on last colon).
func extractIP(remote string) string {
	idx := strings.LastIndex(remote, ":")
	if idx < 0 {
		return remote
	}
	return remote[:idx]
}

// Process processes a connection-related log entry.
func (c *ConnectionAccumulator) Process(entry parser.LogEntry) {
	switch entry.ID {
	case 22943: // connection accepted
		c.totalOpened++
		c.currentConns++
		if c.currentConns > c.peakConns {
			c.peakConns = c.currentConns
		}

		remote := entry.AttrString("remote")
		if remote != "" {
			ip := extractIP(remote)
			c.ipCounts[ip]++
		}

		// Track open connection for duration pairing
		connID := entry.AttrInt("connectionId")
		if connID > 0 {
			c.openConns[connID] = entry.Timestamp
		}

		// Timeline
		minute := entry.Timestamp.Truncate(time.Minute)
		bucket := c.getOrCreateBucket(minute)
		bucket.Opened++
		bucket.ConnectionCount = c.currentConns

	case 22944: // connection ended
		c.totalClosed++
		c.currentConns--

		// Duration pairing
		connID := entry.AttrInt("connectionId")
		if connID > 0 {
			if openTime, ok := c.openConns[connID]; ok {
				dur := entry.Timestamp.Sub(openTime).Seconds() * 1000 // ms
				c.connDurations = append(c.connDurations, dur)
				delete(c.openConns, connID)
			}
		}

		// Timeline
		minute := entry.Timestamp.Truncate(time.Minute)
		bucket := c.getOrCreateBucket(minute)
		bucket.Closed++
		bucket.ConnectionCount = c.currentConns

	case 6723804: // TLS handshake
		durMs := entry.AttrFloat("durationMillis")
		c.tlsDurations = append(c.tlsDurations, durMs)
	}
}

func (c *ConnectionAccumulator) getOrCreateBucket(minute time.Time) *ConnTimelineBucket {
	if bucket, ok := c.timeline[minute]; ok {
		return bucket
	}
	bucket := &ConnTimelineBucket{Minute: minute}
	c.timeline[minute] = bucket
	return bucket
}

// Result returns the connection analysis results.
func (c *ConnectionAccumulator) Result() ConnectionResult {
	// Build ByIP sorted by count desc
	byIP := make([]IPStats, 0, len(c.ipCounts))
	for ip, count := range c.ipCounts {
		byIP = append(byIP, IPStats{IP: ip, Count: count})
	}
	sort.Slice(byIP, func(i, j int) bool {
		return byIP[i].Count > byIP[j].Count
	})

	// Build Timeline sorted by minute
	timeline := make([]ConnTimelineBucket, 0, len(c.timeline))
	for _, bucket := range c.timeline {
		timeline = append(timeline, *bucket)
	}
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Minute.Before(timeline[j].Minute)
	})

	// TLS stats
	var tls TLSStats
	if len(c.tlsDurations) > 0 {
		tls.Count = len(c.tlsDurations)
		sort.Float64s(c.tlsDurations)
		tls.MinMs = c.tlsDurations[0]
		tls.MaxMs = c.tlsDurations[len(c.tlsDurations)-1]

		var sum float64
		for _, d := range c.tlsDurations {
			sum += d
		}
		tls.MeanMs = sum / float64(len(c.tlsDurations))
		tls.P95Ms = percentileFloat(c.tlsDurations, 95)
	}

	// Connection duration stats
	var dur ConnDurationStats
	if len(c.connDurations) > 0 {
		dur.Count = len(c.connDurations)
		sort.Float64s(c.connDurations)
		dur.MinMs = c.connDurations[0]
		dur.MaxMs = c.connDurations[len(c.connDurations)-1]

		var sum float64
		for _, d := range c.connDurations {
			sum += d
		}
		dur.MeanMs = sum / float64(len(c.connDurations))
		dur.P95Ms = percentileFloat(c.connDurations, 95)
	}

	return ConnectionResult{
		TotalOpened:     c.totalOpened,
		TotalClosed:     c.totalClosed,
		PeakConnections: c.peakConns,
		ByIP:            byIP,
		Timeline:        timeline,
		TLS:             tls,
		Duration:        dur,
	}
}

// percentileFloat computes the p-th percentile from a sorted slice of float64s.
func percentileFloat(sorted []float64, p float64) float64 {
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

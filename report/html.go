package report

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"sort"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
)

//go:embed template.html
var templateFS embed.FS

// htmlData wraps analyzer.Results with computed fields for the HTML template.
type htmlData struct {
	analyzer.Results

	DurationHours      float64
	SlowQueryCount     int
	ErrorCount         int
	TopIPs             []analyzer.IPStats
	OpCounts           []OpCount
	ComponentChartJSON template.JS
	MsgTypeChartJSON   template.JS
	TimelineJSON       template.JS
	ScatterJSON        template.JS
	ScatterDetailsJSON template.JS
	BreakdownJSON      template.JS
	ConnTimelineJSON   template.JS
	OpCountsJSON       template.JS
	AIAnalysis         template.HTML
	PlotlyJS           template.JS
}

// OpCount holds the count of slow queries for a specific operation/command type.
type OpCount struct {
	Name    string
	Count   int
	Percent float64
}

// WriteHTML renders the analysis results as an HTML report.
func WriteHTML(w io.Writer, results analyzer.Results, aiAnalysis string) error {
	funcMap := template.FuncMap{
		"comma":    commaFormat,
		"truncate": truncate,
		"bytes":    formatBytes,
		"divf":     divf,
	}

	tmplContent, err := templateFS.ReadFile("template.html")
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	data := buildHTMLData(results, aiAnalysis)
	return tmpl.Execute(w, data)
}

// buildHTMLData creates the template data structure from results.
func buildHTMLData(results analyzer.Results, aiAnalysis string) htmlData {
	// Duration in hours
	var durationHours float64
	if !results.General.StartTime.IsZero() && !results.General.EndTime.IsZero() {
		durationHours = results.General.EndTime.Sub(results.General.StartTime).Hours()
	}

	// Sum slow query counts
	var slowQueryCount int
	for _, grp := range results.SlowQueries.Groups {
		slowQueryCount += grp.Count
	}

	// Sum error counts
	var errorCount int
	for _, grp := range results.Errors.Groups {
		errorCount += grp.Count
	}

	// Cap top IPs at 20
	topIPs := results.Connections.ByIP
	if len(topIPs) > 20 {
		topIPs = topIPs[:20]
	}

	// Aggregate operation counts by command name
	opMap := make(map[string]int)
	for _, grp := range results.SlowQueries.Groups {
		name := grp.CmdName
		if name == "" {
			name = "unknown"
		}
		opMap[name] += grp.Count
	}
	opCounts := make([]OpCount, 0, len(opMap))
	for name, count := range opMap {
		pct := 0.0
		if slowQueryCount > 0 {
			pct = math.Round(float64(count)/float64(slowQueryCount)*1000) / 10
		}
		opCounts = append(opCounts, OpCount{Name: name, Count: count, Percent: pct})
	}
	sort.Slice(opCounts, func(i, j int) bool {
		return opCounts[i].Count > opCounts[j].Count
	})

	return htmlData{
		Results:            results,
		DurationHours:      durationHours,
		SlowQueryCount:     slowQueryCount,
		ErrorCount:         errorCount,
		TopIPs:             topIPs,
		OpCounts:           opCounts,
		ComponentChartJSON: template.JS(buildComponentChartJSON(results)),
		MsgTypeChartJSON:   template.JS(buildMsgTypeChartJSON(results)),
		TimelineJSON:       template.JS(buildTimelineJSON(results)),
		ScatterJSON:        template.JS(buildScatterJSON(results)),
		ScatterDetailsJSON: template.JS(buildScatterDetailsJSON(results)),
		BreakdownJSON:      template.JS(buildBreakdownJSON(results)),
		ConnTimelineJSON:   template.JS(buildConnTimelineJSON(results)),
		OpCountsJSON:       template.JS(buildOpCountsJSON(opCounts)),
		AIAnalysis:         template.HTML(aiAnalysis),
	}
}

// buildTimelineJSON builds Plotly data for the slow query timeline bar chart.
func buildTimelineJSON(results analyzer.Results) string {
	if len(results.SlowQueries.Timeline) == 0 {
		return "[]"
	}

	x := make([]string, len(results.SlowQueries.Timeline))
	y := make([]int, len(results.SlowQueries.Timeline))

	for i, bucket := range results.SlowQueries.Timeline {
		x[i] = bucket.Minute.Format("2006-01-02T15:04:05Z")
		y[i] = bucket.Count
	}

	trace := map[string]interface{}{
		"x":      x,
		"y":      y,
		"type":   "bar",
		"name":   "Slow Queries",
		"marker": map[string]string{"color": "#58a6ff"},
	}

	data := []interface{}{trace}
	b, _ := json.Marshal(data)
	return string(b)
}

// buildScatterJSON builds Plotly data for the slow query scatter chart.
func buildScatterJSON(results analyzer.Results) string {
	if len(results.SlowQueries.Groups) == 0 {
		return "[]"
	}

	x := make([]int, len(results.SlowQueries.Groups))
	y := make([]int, len(results.SlowQueries.Groups))
	text := make([]string, len(results.SlowQueries.Groups))
	sizes := make([]int, len(results.SlowQueries.Groups))

	for i, grp := range results.SlowQueries.Groups {
		x[i] = grp.Count
		y[i] = grp.MeanMs
		text[i] = fmt.Sprintf("%s.%s<br>Count: %d<br>Mean: %dms<br>P95: %dms",
			grp.Namespace, grp.CmdName, grp.Count, grp.MeanMs, grp.P95Ms)
		// Size proportional to total time, min 6, max 40
		sz := int(math.Sqrt(float64(grp.SumMs))) / 2
		if sz < 6 {
			sz = 6
		}
		if sz > 40 {
			sz = 40
		}
		sizes[i] = sz
	}

	trace := map[string]interface{}{
		"x":        x,
		"y":        y,
		"text":     text,
		"type":     "scattergl",
		"mode":     "markers",
		"name":     "Query Patterns",
		"hoverinfo": "text",
		"marker": map[string]interface{}{
			"size":    sizes,
			"color":   "#58a6ff",
			"opacity": 0.7,
		},
	}

	data := []interface{}{trace}
	b, _ := json.Marshal(data)
	return string(b)
}

// buildScatterDetailsJSON builds per-point detail data for the scatter chart click modal.
func buildScatterDetailsJSON(results analyzer.Results) string {
	if len(results.SlowQueries.Groups) == 0 {
		return "[]"
	}

	type detail struct {
		Namespace    string                 `json:"namespace"`
		CmdName      string                 `json:"cmdName"`
		Pattern      string                 `json:"pattern"`
		Count        int                    `json:"count"`
		MinMs        int                    `json:"minMs"`
		MaxMs        int                    `json:"maxMs"`
		MeanMs       int                    `json:"meanMs"`
		P95Ms        int                    `json:"p95Ms"`
		SumMs        int                    `json:"sumMs"`
		SampleCmd    map[string]interface{} `json:"sampleCmd"`
	}

	details := make([]detail, len(results.SlowQueries.Groups))
	for i, grp := range results.SlowQueries.Groups {
		details[i] = detail{
			Namespace: grp.Namespace,
			CmdName:   grp.CmdName,
			Pattern:   grp.Pattern,
			Count:     grp.Count,
			MinMs:     grp.MinMs,
			MaxMs:     grp.MaxMs,
			MeanMs:    grp.MeanMs,
			P95Ms:     grp.P95Ms,
			SumMs:     grp.SumMs,
			SampleCmd: grp.SampleCommand,
		}
	}

	b, _ := json.Marshal(details)
	return string(b)
}

// buildComponentChartJSON builds a donut chart of all log entries by component.
func buildComponentChartJSON(results analyzer.Results) string {
	if len(results.General.ComponentCounts) == 0 {
		return "[]"
	}

	type kv struct {
		k string
		v int
	}
	var items []kv
	for k, v := range results.General.ComponentCounts {
		name := k
		if name == "-" {
			name = "DEFAULT"
		}
		items = append(items, kv{name, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].v > items[j].v })

	labels := make([]string, len(items))
	values := make([]int, len(items))
	for i, item := range items {
		labels[i] = item.k
		values[i] = item.v
	}

	colors := []string{"#58a6ff", "#3fb950", "#d29922", "#f85149", "#bc8cff", "#f778ba", "#79c0ff", "#56d364", "#e3b341", "#ff7b72"}
	traceColors := make([]string, len(items))
	for i := range items {
		traceColors[i] = colors[i%len(colors)]
	}

	trace := map[string]interface{}{
		"labels":       labels,
		"values":       values,
		"type":         "pie",
		"hole":         0.4,
		"textinfo":     "label+percent",
		"textposition": "outside",
		"marker":       map[string]interface{}{"colors": traceColors},
	}
	b, _ := json.Marshal([]interface{}{trace})
	return string(b)
}

// buildMsgTypeChartJSON builds a horizontal bar chart of top message types.
func buildMsgTypeChartJSON(results analyzer.Results) string {
	msgs := results.General.TopMessages
	if len(msgs) == 0 {
		return "[]"
	}

	labels := make([]string, len(msgs))
	values := make([]int, len(msgs))
	for i, m := range msgs {
		labels[len(msgs)-1-i] = m.Message
		values[len(msgs)-1-i] = m.Count
	}

	trace := map[string]interface{}{
		"y":           labels,
		"x":           values,
		"type":        "bar",
		"orientation": "h",
		"marker":      map[string]string{"color": "#58a6ff"},
	}
	b, _ := json.Marshal([]interface{}{trace})
	return string(b)
}

// buildOpCountsJSON builds Plotly data for the operation counts pie chart.
func buildOpCountsJSON(opCounts []OpCount) string {
	if len(opCounts) == 0 {
		return "[]"
	}

	labels := make([]string, len(opCounts))
	values := make([]int, len(opCounts))
	for i, oc := range opCounts {
		labels[i] = oc.Name
		values[i] = oc.Count
	}

	colors := []string{"#58a6ff", "#3fb950", "#d29922", "#f85149", "#bc8cff", "#f778ba", "#79c0ff", "#56d364", "#e3b341", "#ff7b72"}

	traceColors := make([]string, len(opCounts))
	for i := range opCounts {
		traceColors[i] = colors[i%len(colors)]
	}

	trace := map[string]interface{}{
		"labels":  labels,
		"values":  values,
		"type":    "pie",
		"hole":    0.4,
		"textinfo": "label+percent",
		"textposition": "outside",
		"marker": map[string]interface{}{
			"colors": traceColors,
		},
	}

	b, _ := json.Marshal([]interface{}{trace})
	return string(b)
}

// buildBreakdownJSON builds Plotly data for the duration breakdown stacked horizontal bar.
func buildBreakdownJSON(results analyzer.Results) string {
	groups := results.SlowQueries.Groups
	if len(groups) == 0 {
		return "[]"
	}

	// Cap to top 15 patterns
	limit := 15
	if len(groups) < limit {
		limit = len(groups)
	}
	groups = groups[:limit]

	labels := make([]string, limit)
	indices := make([]int, limit)
	cpuMs := make([]float64, limit)
	writeConcernMs := make([]float64, limit)
	storageMs := make([]float64, limit)
	otherMs := make([]float64, limit)

	for i, grp := range groups {
		label := grp.Namespace
		if grp.CmdName != "" {
			label += "." + grp.CmdName
		}
		if len(label) > 40 {
			label = label[:37] + "..."
		}
		labels[i] = label
		indices[i] = i

		cpu := float64(grp.MeanCPUNanos) / 1e6
		wc := float64(grp.MeanWriteConcernMs)
		stor := float64(grp.MeanStorageWaitUs) / 1e3
		total := float64(grp.MeanMs)

		accounted := cpu + wc + stor
		other := total - accounted
		if other < 0 {
			other = 0
		}

		cpuMs[i] = math.Round(cpu*100) / 100
		writeConcernMs[i] = math.Round(wc*100) / 100
		storageMs[i] = math.Round(stor*100) / 100
		otherMs[i] = math.Round(other*100) / 100
	}

	traces := []interface{}{
		map[string]interface{}{
			"y":           labels,
			"x":           cpuMs,
			"customdata":  indices,
			"name":        "CPU",
			"type":        "bar",
			"orientation": "h",
			"marker":      map[string]string{"color": "#58a6ff"},
		},
		map[string]interface{}{
			"y":           labels,
			"x":           writeConcernMs,
			"customdata":  indices,
			"name":        "Write Concern",
			"type":        "bar",
			"orientation": "h",
			"marker":      map[string]string{"color": "#d29922"},
		},
		map[string]interface{}{
			"y":           labels,
			"x":           storageMs,
			"customdata":  indices,
			"name":        "Storage Wait",
			"type":        "bar",
			"orientation": "h",
			"marker":      map[string]string{"color": "#3fb950"},
		},
		map[string]interface{}{
			"y":           labels,
			"x":           otherMs,
			"customdata":  indices,
			"name":        "Other",
			"type":        "bar",
			"orientation": "h",
			"marker":      map[string]string{"color": "#8b949e"},
		},
	}

	b, _ := json.Marshal(traces)
	return string(b)
}

// buildConnTimelineJSON builds Plotly data for the connection timeline area chart.
func buildConnTimelineJSON(results analyzer.Results) string {
	if len(results.Connections.Timeline) == 0 {
		return "[]"
	}

	x := make([]string, len(results.Connections.Timeline))
	yConns := make([]int, len(results.Connections.Timeline))
	yOpened := make([]int, len(results.Connections.Timeline))
	yClosed := make([]int, len(results.Connections.Timeline))

	for i, bucket := range results.Connections.Timeline {
		x[i] = bucket.Minute.Format("2006-01-02T15:04:05Z")
		yConns[i] = bucket.ConnectionCount
		yOpened[i] = bucket.Opened
		yClosed[i] = bucket.Closed
	}

	traces := []interface{}{
		map[string]interface{}{
			"x":    x,
			"y":    yConns,
			"type": "scatter",
			"mode": "lines",
			"fill": "tozeroy",
			"name": "Active Connections",
			"line": map[string]string{"color": "#58a6ff"},
		},
		map[string]interface{}{
			"x":    x,
			"y":    yOpened,
			"type": "scatter",
			"mode": "lines",
			"name": "Opened / min",
			"line": map[string]interface{}{"color": "#3fb950", "dash": "dot"},
		},
		map[string]interface{}{
			"x":    x,
			"y":    yClosed,
			"type": "scatter",
			"mode": "lines",
			"name": "Closed / min",
			"line": map[string]interface{}{"color": "#f85149", "dash": "dot"},
		},
	}

	b, _ := json.Marshal(traces)
	return string(b)
}

// commaFormat formats an integer with comma separators.
// Handles both int and int64.
func commaFormat(v interface{}) string {
	var n int64
	switch val := v.(type) {
	case int:
		n = int64(val)
	case int64:
		n = val
	default:
		return fmt.Sprintf("%v", v)
	}

	if n < 0 {
		return "-" + commaFormat(-n)
	}

	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	var result []byte
	remainder := len(s) % 3
	if remainder > 0 {
		result = append(result, s[:remainder]...)
		if len(s) > remainder {
			result = append(result, ',')
		}
	}
	for i := remainder; i < len(s); i += 3 {
		result = append(result, s[i:i+3]...)
		if i+3 < len(s) {
			result = append(result, ',')
		}
	}
	return string(result)
}

// truncate shortens a string to maxLen characters, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// formatBytes formats a byte count into a human-readable string.
func formatBytes(b int64) string {
	if b < 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), units[exp])
}

// divf divides an int64 by a float64, returning a float64 for template use.
func divf(a int64, b float64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / b
}

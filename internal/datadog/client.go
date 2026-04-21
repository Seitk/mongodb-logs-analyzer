package datadog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/internal/analyzer"
)

const defaultSite = "datadoghq.com"

type Client struct {
	APIKey string
	Site   string
	HTTP   *http.Client
	Host   string // tag value for host, derived from log context
}

func NewClient(apiKey, site string) *Client {
	if site == "" {
		site = defaultSite
	}
	return &Client{
		APIKey: apiKey,
		Site:   site,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
	}
}

type series struct {
	Series []metric `json:"series"`
}

type metric struct {
	Metric   string   `json:"metric"`
	Type     int      `json:"type"` // 1=count, 2=rate, 3=gauge
	Points   []point  `json:"points"`
	Tags     []string `json:"tags"`
	Unit     string   `json:"unit,omitempty"`
}

type point struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

func (c *Client) SubmitMetrics(results analyzer.Results) error {
	ts := results.General.EndTime.Unix()
	host := results.General.Host
	if host == "" {
		host = "unknown"
	}
	c.Host = host

	var metrics []metric

	// Slow query metrics
	for _, g := range results.SlowQueries.Groups {
		db, coll := splitNamespace(g.Namespace)
		tags := []string{
			"namespace:" + g.Namespace,
			"db:" + db,
			"collection:" + coll,
			"command:" + g.CmdName,
			"host:" + host,
		}
		if g.Pattern != "" {
			tags = append(tags, "pattern:"+g.Pattern)
		}

		metrics = append(metrics,
			gauge("mongodb.slow_query.count", float64(g.Count), ts, tags),
			gauge("mongodb.slow_query.duration.avg", float64(g.MeanMs), ts, tags),
			gauge("mongodb.slow_query.duration.p95", float64(g.P95Ms), ts, tags),
			gauge("mongodb.slow_query.duration.max", float64(g.MaxMs), ts, tags),
			gauge("mongodb.slow_query.duration.sum", float64(g.SumMs), ts, tags),
			gauge("mongodb.slow_query.cpu_nanos.avg", float64(g.MeanCPUNanos), ts, tags),
			gauge("mongodb.slow_query.write_concern_wait.avg", float64(g.MeanWriteConcernMs), ts, tags),
			gauge("mongodb.slow_query.storage_wait.avg", float64(g.MeanStorageWaitUs), ts, tags),
		)
	}

	// Table scan metrics
	scansByNS := make(map[string]int)
	for _, s := range results.TableScans.Scans {
		scansByNS[s.Namespace]++
	}
	for ns, count := range scansByNS {
		db, coll := splitNamespace(ns)
		tags := []string{"namespace:" + ns, "db:" + db, "collection:" + coll, "host:" + host}
		metrics = append(metrics, gauge("mongodb.table_scan.count", float64(count), ts, tags))
	}

	// Connection metrics
	connTags := []string{"host:" + host}
	metrics = append(metrics,
		gauge("mongodb.connections.opened", float64(results.Connections.TotalOpened), ts, connTags),
		gauge("mongodb.connections.closed", float64(results.Connections.TotalClosed), ts, connTags),
		gauge("mongodb.connections.peak", float64(results.Connections.PeakConnections), ts, connTags),
	)
	if results.Connections.TLS.Count > 0 {
		metrics = append(metrics,
			gauge("mongodb.connections.tls_handshake.p95", float64(results.Connections.TLS.P95Ms), ts, connTags),
		)
	}

	// Log line metrics by severity
	for sev, count := range results.General.SeverityCounts {
		tags := []string{"host:" + host, "severity:" + sev}
		metrics = append(metrics, gauge("mongodb.log.lines", float64(count), ts, tags))
	}

	// Log line metrics by component
	for comp, count := range results.General.ComponentCounts {
		tags := []string{"host:" + host, "component:" + comp}
		metrics = append(metrics, gauge("mongodb.log.lines_by_component", float64(count), ts, tags))
	}

	// Error metrics
	for _, g := range results.Errors.Groups {
		tags := []string{"host:" + host, "severity:" + g.Severity, "component:" + g.Component, "message:" + g.Message}
		metrics = append(metrics, gauge("mongodb.log.errors", float64(g.Count), ts, tags))
	}

	// Client metrics
	for _, g := range results.Clients.Groups {
		tags := []string{"host:" + host, "driver:" + g.DriverName, "driver_version:" + g.DriverVersion, "app_name:" + g.AppName}
		metrics = append(metrics, gauge("mongodb.client.connections", float64(g.Count), ts, tags))
	}

	// Storage metrics
	for _, s := range results.Storage.Namespaces {
		db, coll := splitNamespace(s.Namespace)
		tags := []string{"namespace:" + s.Namespace, "db:" + db, "collection:" + coll, "host:" + host}
		metrics = append(metrics,
			gauge("mongodb.storage.bytes_read", float64(s.TotalBytesRead), ts, tags),
			gauge("mongodb.storage.bytes_written", float64(s.TotalBytesWritten), ts, tags),
			gauge("mongodb.storage.read_time_us", float64(s.TotalTimeReadUs), ts, tags),
		)
	}

	// Transaction metrics
	txnByNS := make(map[string][]int)
	for _, t := range results.Transactions.Transactions {
		txnByNS[t.Namespace] = append(txnByNS[t.Namespace], t.DurationMs)
	}
	for ns, durations := range txnByNS {
		db, coll := splitNamespace(ns)
		tags := []string{"namespace:" + ns, "db:" + db, "collection:" + coll, "host:" + host}
		avg := 0.0
		for _, d := range durations {
			avg += float64(d)
		}
		if len(durations) > 0 {
			avg /= float64(len(durations))
		}
		metrics = append(metrics,
			gauge("mongodb.transactions.count", float64(len(durations)), ts, tags),
			gauge("mongodb.transactions.duration.avg", avg, ts, tags),
		)
	}

	// Submit in batches of 500
	for i := 0; i < len(metrics); i += 500 {
		end := i + 500
		if end > len(metrics) {
			end = len(metrics)
		}
		if err := c.submit(metrics[i:end]); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) submit(metrics []metric) error {
	payload := series{Series: metrics}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal metrics: %w", err)
	}

	url := fmt.Sprintf("https://api.%s/api/v2/series", c.Site)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("submit metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var respBody bytes.Buffer
		respBody.ReadFrom(resp.Body)
		return fmt.Errorf("Datadog API HTTP %d: %s", resp.StatusCode, respBody.String())
	}

	return nil
}

func gauge(name string, value float64, ts int64, tags []string) metric {
	return metric{
		Metric: name,
		Type:   3, // gauge
		Points: []point{{Timestamp: ts, Value: value}},
		Tags:   tags,
	}
}

func splitNamespace(ns string) (db, collection string) {
	parts := strings.SplitN(ns, ".", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return ns, ""
}

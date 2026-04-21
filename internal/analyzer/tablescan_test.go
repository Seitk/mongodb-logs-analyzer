package analyzer

import (
	"testing"
)

func TestTableScanAccumulator_COLLSCAN(t *testing.T) {
	acc := NewTableScanAccumulator()

	e := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
	e.Attr = map[string]interface{}{
		"ns":             "db.users",
		"planSummary":    "COLLSCAN",
		"docsExamined":   float64(500),
		"keysExamined":   float64(0),
		"nreturned":      float64(10),
		"durationMillis": float64(200),
	}
	acc.Process(e)

	result := acc.Result()
	if len(result.Scans) != 1 {
		t.Fatalf("len(Scans) = %d, want 1", len(result.Scans))
	}
	if result.Scans[0].PlanSummary != "COLLSCAN" {
		t.Errorf("PlanSummary = %q, want %q", result.Scans[0].PlanSummary, "COLLSCAN")
	}
}

func TestTableScanAccumulator_HighRatio(t *testing.T) {
	acc := NewTableScanAccumulator()

	e := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
	e.Attr = map[string]interface{}{
		"ns":             "db.orders",
		"planSummary":    "IXSCAN { status: 1 }",
		"docsExamined":   float64(50000),
		"keysExamined":   float64(50000),
		"nreturned":      float64(5),
		"durationMillis": float64(1500),
	}
	acc.Process(e)

	result := acc.Result()
	if len(result.Scans) != 1 {
		t.Fatalf("len(Scans) = %d, want 1", len(result.Scans))
	}
	if result.Scans[0].DocsExamined != 50000 {
		t.Errorf("DocsExamined = %d, want 50000", result.Scans[0].DocsExamined)
	}
}

func TestTableScanAccumulator_NoDetection(t *testing.T) {
	acc := NewTableScanAccumulator()

	// Normal query: IXSCAN, low docs examined, good ratio
	e := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
	e.Attr = map[string]interface{}{
		"ns":             "db.users",
		"planSummary":    "IXSCAN { _id: 1 }",
		"docsExamined":   float64(100),
		"keysExamined":   float64(100),
		"nreturned":      float64(100),
		"durationMillis": float64(200),
	}
	acc.Process(e)

	result := acc.Result()
	if len(result.Scans) != 0 {
		t.Errorf("len(Scans) = %d, want 0", len(result.Scans))
	}
}

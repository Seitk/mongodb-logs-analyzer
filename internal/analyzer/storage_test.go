package analyzer

import (
	"testing"
)

func TestStorageAccumulator_PerNamespace(t *testing.T) {
	acc := NewStorageAccumulator()

	// Namespace 1: db.users - 2 ops, more reads
	e1 := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
	e1.Attr = map[string]interface{}{
		"ns": "db.users",
		"storage": map[string]interface{}{
			"data": map[string]interface{}{
				"bytesRead":         float64(10000),
				"bytesWritten":      float64(500),
				"timeReadingMicros": float64(200),
				"timeWritingMicros": float64(50),
			},
		},
	}
	acc.Process(e1)

	e2 := makeEntry("2024-01-01T00:00:01Z", "I", "COMMAND", 51803, "Slow query")
	e2.Attr = map[string]interface{}{
		"ns": "db.users",
		"storage": map[string]interface{}{
			"data": map[string]interface{}{
				"bytesRead":         float64(20000),
				"bytesWritten":      float64(1000),
				"timeReadingMicros": float64(300),
				"timeWritingMicros": float64(100),
			},
		},
	}
	acc.Process(e2)

	// Namespace 2: db.orders - 1 op, fewer reads
	e3 := makeEntry("2024-01-01T00:00:02Z", "I", "COMMAND", 51803, "Slow query")
	e3.Attr = map[string]interface{}{
		"ns": "db.orders",
		"storage": map[string]interface{}{
			"data": map[string]interface{}{
				"bytesRead":         float64(5000),
				"bytesWritten":      float64(2000),
				"timeReadingMicros": float64(100),
				"timeWritingMicros": float64(200),
			},
		},
	}
	acc.Process(e3)

	result := acc.Result()

	if len(result.Namespaces) != 2 {
		t.Fatalf("len(Namespaces) = %d, want 2", len(result.Namespaces))
	}

	// Sorted by TotalBytesRead desc
	if result.Namespaces[0].Namespace != "db.users" {
		t.Errorf("Namespaces[0].Namespace = %q, want %q", result.Namespaces[0].Namespace, "db.users")
	}
	if result.Namespaces[0].TotalBytesRead != 30000 {
		t.Errorf("TotalBytesRead = %d, want 30000", result.Namespaces[0].TotalBytesRead)
	}
	if result.Namespaces[0].TotalBytesWritten != 1500 {
		t.Errorf("TotalBytesWritten = %d, want 1500", result.Namespaces[0].TotalBytesWritten)
	}
	if result.Namespaces[0].OpCount != 2 {
		t.Errorf("OpCount = %d, want 2", result.Namespaces[0].OpCount)
	}
	if result.Namespaces[0].MeanBytesRead != 15000 {
		t.Errorf("MeanBytesRead = %d, want 15000", result.Namespaces[0].MeanBytesRead)
	}
	if result.Namespaces[0].MeanBytesWritten != 750 {
		t.Errorf("MeanBytesWritten = %d, want 750", result.Namespaces[0].MeanBytesWritten)
	}

	if result.Namespaces[1].Namespace != "db.orders" {
		t.Errorf("Namespaces[1].Namespace = %q, want %q", result.Namespaces[1].Namespace, "db.orders")
	}
	if result.Namespaces[1].TotalBytesRead != 5000 {
		t.Errorf("TotalBytesRead = %d, want 5000", result.Namespaces[1].TotalBytesRead)
	}
}

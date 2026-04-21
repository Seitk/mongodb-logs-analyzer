package analyzer

import (
	"testing"
)

func TestClientAccumulator_Grouping(t *testing.T) {
	acc := NewClientAccumulator()

	// Group 1: Node.js driver (2 entries from different IPs)
	e1 := makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 51800, "client metadata")
	e1.Attr = map[string]interface{}{
		"remote": "10.0.0.1:5000",
		"doc": map[string]interface{}{
			"driver":      map[string]interface{}{"name": "nodejs", "version": "5.0.0"},
			"application": map[string]interface{}{"name": "myapp"},
		},
	}
	acc.Process(e1)

	e2 := makeEntry("2024-01-01T00:00:01Z", "I", "NETWORK", 51800, "client metadata")
	e2.Attr = map[string]interface{}{
		"remote": "10.0.0.2:6000",
		"doc": map[string]interface{}{
			"driver":      map[string]interface{}{"name": "nodejs", "version": "5.0.0"},
			"application": map[string]interface{}{"name": "myapp"},
		},
	}
	acc.Process(e2)

	// Group 2: Python driver (1 entry)
	e3 := makeEntry("2024-01-01T00:00:02Z", "I", "NETWORK", 51800, "client metadata")
	e3.Attr = map[string]interface{}{
		"remote": "10.0.0.3:7000",
		"doc": map[string]interface{}{
			"driver":      map[string]interface{}{"name": "pymongo", "version": "4.6.0"},
			"application": map[string]interface{}{"name": "worker"},
		},
	}
	acc.Process(e3)

	result := acc.Result()

	if len(result.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(result.Groups))
	}

	// Sorted by count desc
	if result.Groups[0].DriverName != "nodejs" {
		t.Errorf("Groups[0].DriverName = %q, want %q", result.Groups[0].DriverName, "nodejs")
	}
	if result.Groups[0].Count != 2 {
		t.Errorf("Groups[0].Count = %d, want 2", result.Groups[0].Count)
	}
	if len(result.Groups[0].UniqueIPs) != 2 {
		t.Errorf("Groups[0].UniqueIPs = %d, want 2", len(result.Groups[0].UniqueIPs))
	}

	if result.Groups[1].DriverName != "pymongo" {
		t.Errorf("Groups[1].DriverName = %q, want %q", result.Groups[1].DriverName, "pymongo")
	}
	if result.Groups[1].Count != 1 {
		t.Errorf("Groups[1].Count = %d, want 1", result.Groups[1].Count)
	}
}

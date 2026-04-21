package analyzer

import (
	"testing"
)

func TestErrorAccumulator_CollectsWarnings(t *testing.T) {
	acc := NewErrorAccumulator()

	// Warning - should be collected
	acc.Process(makeEntry("2024-01-01T00:00:00Z", "W", "STORAGE", 1, "disk nearly full"))
	// Info - should be skipped
	acc.Process(makeEntry("2024-01-01T00:00:01Z", "I", "NETWORK", 2, "connection accepted"))
	// Error - should be collected
	acc.Process(makeEntry("2024-01-01T00:00:02Z", "E", "NETWORK", 3, "connection refused"))

	result := acc.Result()

	if len(result.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(result.Groups))
	}

	// Both have count 1
	found := map[string]bool{}
	for _, g := range result.Groups {
		found[g.Severity] = true
	}
	if !found["W"] {
		t.Error("missing warning group")
	}
	if !found["E"] {
		t.Error("missing error group")
	}
}

func TestErrorAccumulator_GroupsBySeverityComponentMsg(t *testing.T) {
	acc := NewErrorAccumulator()

	// Same severity+component+msg: should be one group with count 3
	acc.Process(makeEntry("2024-01-01T00:00:00Z", "E", "NETWORK", 1, "connection timeout"))
	acc.Process(makeEntry("2024-01-01T00:01:00Z", "E", "NETWORK", 1, "connection timeout"))
	acc.Process(makeEntry("2024-01-01T00:02:00Z", "E", "NETWORK", 1, "connection timeout"))

	// Different message: separate group
	acc.Process(makeEntry("2024-01-01T00:03:00Z", "E", "NETWORK", 2, "connection refused"))

	// Different component: separate group
	acc.Process(makeEntry("2024-01-01T00:04:00Z", "E", "STORAGE", 3, "disk full"))

	result := acc.Result()

	if len(result.Groups) != 3 {
		t.Fatalf("len(Groups) = %d, want 3", len(result.Groups))
	}

	// Sorted by count desc
	if result.Groups[0].Count != 3 {
		t.Errorf("Groups[0].Count = %d, want 3", result.Groups[0].Count)
	}
	if result.Groups[0].Message != "connection timeout" {
		t.Errorf("Groups[0].Message = %q, want %q", result.Groups[0].Message, "connection timeout")
	}
}

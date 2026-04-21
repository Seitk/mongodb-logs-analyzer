package analyzer

import (
	"testing"
)

func TestDistinctAccumulator_Frequency(t *testing.T) {
	acc := NewDistinctAccumulator()

	// Pattern A: 5 times
	for i := 0; i < 5; i++ {
		acc.Process(makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 1, "Slow query"))
	}

	// Pattern B: 3 times
	for i := 0; i < 3; i++ {
		acc.Process(makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 2, "Connection accepted"))
	}

	result := acc.Result()

	if len(result.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(result.Groups))
	}

	if result.Groups[0].Message != "Slow query" {
		t.Errorf("Groups[0].Message = %q, want %q", result.Groups[0].Message, "Slow query")
	}
	if result.Groups[0].Count != 5 {
		t.Errorf("Groups[0].Count = %d, want 5", result.Groups[0].Count)
	}

	if result.Groups[1].Message != "Connection accepted" {
		t.Errorf("Groups[1].Message = %q, want %q", result.Groups[1].Message, "Connection accepted")
	}
	if result.Groups[1].Count != 3 {
		t.Errorf("Groups[1].Count = %d, want 3", result.Groups[1].Count)
	}
}

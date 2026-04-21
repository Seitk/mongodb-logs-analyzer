package analyzer

import (
	"testing"
)

func TestRSStateAccumulator_NoTransitions(t *testing.T) {
	acc := NewRSStateAccumulator()

	// Non-REPL component
	acc.Process(makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 1, "something happened"))
	// REPL but no transition keywords
	acc.Process(makeEntry("2024-01-01T00:00:01Z", "I", "REPL", 2, "heartbeat received"))

	result := acc.Result()

	if len(result.Events) != 0 {
		t.Errorf("len(Events) = %d, want 0", len(result.Events))
	}
}

func TestRSStateAccumulator_DetectsTransition(t *testing.T) {
	acc := NewRSStateAccumulator()

	acc.Process(makeEntry("2024-01-01T00:00:00Z", "I", "REPL", 1, "Member state transition: SECONDARY -> PRIMARY"))
	acc.Process(makeEntry("2024-01-01T00:00:01Z", "I", "REPL", 2, "Replica set state change detected"))
	// This should NOT match (wrong component)
	acc.Process(makeEntry("2024-01-01T00:00:02Z", "I", "NETWORK", 3, "transition to new state"))

	result := acc.Result()

	if len(result.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(result.Events))
	}
	if result.Events[0].Message != "Member state transition: SECONDARY -> PRIMARY" {
		t.Errorf("Events[0].Message = %q", result.Events[0].Message)
	}
	if result.Events[1].Message != "Replica set state change detected" {
		t.Errorf("Events[1].Message = %q", result.Events[1].Message)
	}
}

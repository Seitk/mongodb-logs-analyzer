package analyzer

import (
	"testing"
)

func TestTransactionAccumulator_DetectsTxn(t *testing.T) {
	acc := NewTransactionAccumulator()

	e := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
	e.Attr = map[string]interface{}{
		"ns":             "db.users",
		"durationMillis": float64(500),
		"command": map[string]interface{}{
			"find":      "users",
			"txnNumber": float64(42),
			"readConcern": map[string]interface{}{
				"level": "snapshot",
			},
		},
		"timeActiveMicros":   float64(450000),
		"timeInactiveMicros": float64(50000),
		"terminationCause":   "committed",
	}
	acc.Process(e)

	result := acc.Result()

	if len(result.Transactions) != 1 {
		t.Fatalf("len(Transactions) = %d, want 1", len(result.Transactions))
	}

	txn := result.Transactions[0]
	if txn.TxnNumber != 42 {
		t.Errorf("TxnNumber = %d, want 42", txn.TxnNumber)
	}
	if txn.ReadConcern != "snapshot" {
		t.Errorf("ReadConcern = %q, want %q", txn.ReadConcern, "snapshot")
	}
	if txn.DurationMs != 500 {
		t.Errorf("DurationMs = %d, want 500", txn.DurationMs)
	}
	if txn.TimeActiveMicros != 450000 {
		t.Errorf("TimeActiveMicros = %d, want 450000", txn.TimeActiveMicros)
	}
}

func TestTransactionAccumulator_SkipsNonTxn(t *testing.T) {
	acc := NewTransactionAccumulator()

	// No txnNumber in command
	e := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
	e.Attr = map[string]interface{}{
		"ns":             "db.users",
		"durationMillis": float64(500),
		"command":        map[string]interface{}{"find": "users"},
	}
	acc.Process(e)

	result := acc.Result()

	if len(result.Transactions) != 0 {
		t.Errorf("len(Transactions) = %d, want 0", len(result.Transactions))
	}
}

package analyzer

import (
	"time"

	"github.com/anthropics/mla/parser"
)

// TransactionEntry represents a detected transaction.
type TransactionEntry struct {
	Timestamp         time.Time
	Namespace         string
	TxnNumber         int
	DurationMs        int
	ReadConcern       string
	TimeActiveMicros  int
	TimeInactiveMicros int
	TerminationCause  string
}

// TransactionResult holds all detected transactions.
type TransactionResult struct {
	Transactions []TransactionEntry
}

// TransactionAccumulator detects transactions in slow query entries.
type TransactionAccumulator struct {
	transactions []TransactionEntry
}

// NewTransactionAccumulator creates a new TransactionAccumulator.
func NewTransactionAccumulator() *TransactionAccumulator {
	return &TransactionAccumulator{}
}

// Process checks if a slow query entry is a transaction.
func (t *TransactionAccumulator) Process(entry parser.LogEntry) {
	cmd := entry.AttrMap("command")
	if cmd == nil {
		return
	}

	txnRaw, ok := cmd["txnNumber"]
	if !ok {
		return
	}

	txnFloat, ok := txnRaw.(float64)
	if !ok {
		return
	}

	txn := TransactionEntry{
		Timestamp:  entry.Timestamp,
		Namespace:  entry.AttrString("ns"),
		TxnNumber:  int(txnFloat),
		DurationMs: entry.AttrInt("durationMillis"),
	}

	// Read concern
	if rcMap, ok := cmd["readConcern"].(map[string]interface{}); ok {
		if level, ok := rcMap["level"].(string); ok {
			txn.ReadConcern = level
		}
	}

	txn.TimeActiveMicros = entry.AttrInt("timeActiveMicros")
	txn.TimeInactiveMicros = entry.AttrInt("timeInactiveMicros")
	txn.TerminationCause = entry.AttrString("terminationCause")

	t.transactions = append(t.transactions, txn)
}

// Result returns the transaction results.
func (t *TransactionAccumulator) Result() TransactionResult {
	return TransactionResult{Transactions: t.transactions}
}

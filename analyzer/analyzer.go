package analyzer

import "github.com/Seitk/mongodb-logs-analyzer/parser"

// Accumulator is the interface that all log accumulators implement.
type Accumulator interface {
	Process(entry parser.LogEntry)
}

// Results holds the output from all accumulators after analysis.
type Results struct {
	General      GeneralResult
	SlowQueries  SlowQueryResult
	TableScans   TableScanResult
	Connections  ConnectionResult
	Clients      ClientResult
	Distinct     DistinctResult
	RSState      RSStateResult
	Storage      StorageResult
	Transactions TransactionResult
	Errors       ErrorResult
}

// Analyzer orchestrates all accumulators.
type Analyzer struct {
	general     *GeneralAccumulator
	slowQuery   *SlowQueryAccumulator
	tableScan   *TableScanAccumulator
	connection  *ConnectionAccumulator
	client      *ClientAccumulator
	distinct    *DistinctAccumulator
	rsState     *RSStateAccumulator
	storage     *StorageAccumulator
	transaction *TransactionAccumulator
	errors      *ErrorAccumulator
	slowMS      int
}

// New creates a new Analyzer with the given slow query threshold in milliseconds.
func New(slowMS int) *Analyzer {
	return &Analyzer{
		general:     NewGeneralAccumulator(),
		slowQuery:   NewSlowQueryAccumulator(),
		tableScan:   NewTableScanAccumulator(),
		connection:  NewConnectionAccumulator(),
		client:      NewClientAccumulator(),
		distinct:    NewDistinctAccumulator(),
		rsState:     NewRSStateAccumulator(),
		storage:     NewStorageAccumulator(),
		transaction: NewTransactionAccumulator(),
		errors:      NewErrorAccumulator(),
		slowMS:      slowMS,
	}
}

// Process sends a log entry through all relevant accumulators.
func (a *Analyzer) Process(entry parser.LogEntry) {
	a.general.Process(entry)
	a.distinct.Process(entry)
	a.errors.Process(entry)
	a.connection.Process(entry)
	a.client.Process(entry)
	a.rsState.Process(entry)

	if entry.ID == 51803 {
		dur := entry.AttrInt("durationMillis")
		if dur >= a.slowMS {
			a.slowQuery.Process(entry)
		}
		a.tableScan.Process(entry)
		a.storage.Process(entry)
		a.transaction.Process(entry)
	}
}

// Finalize collects results from all accumulators.
func (a *Analyzer) Finalize() Results {
	return Results{
		General:      a.general.Result(),
		SlowQueries:  a.slowQuery.Result(),
		TableScans:   a.tableScan.Result(),
		Connections:  a.connection.Result(),
		Clients:      a.client.Result(),
		Distinct:     a.distinct.Result(),
		RSState:      a.rsState.Result(),
		Storage:      a.storage.Result(),
		Transactions: a.transaction.Result(),
		Errors:       a.errors.Result(),
	}
}

// Run scans a log file and returns the analysis results.
func (a *Analyzer) Run(path string) (Results, error) {
	err := parser.ScanFile(path, func(entry parser.LogEntry) {
		a.Process(entry)
	})
	if err != nil {
		return Results{}, err
	}
	return a.Finalize(), nil
}

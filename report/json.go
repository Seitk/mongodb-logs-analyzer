package report

import (
	"encoding/json"
	"io"

	"github.com/anthropics/mla/analyzer"
)

// jsonOutput defines the top-level JSON structure for serialization.
type jsonOutput struct {
	General      analyzer.GeneralResult      `json:"general"`
	SlowQueries  analyzer.SlowQueryResult    `json:"slowQueries"`
	TableScans   analyzer.TableScanResult    `json:"tableScans"`
	Connections  analyzer.ConnectionResult   `json:"connections"`
	Clients      analyzer.ClientResult       `json:"clients"`
	Distinct     analyzer.DistinctResult     `json:"distinct"`
	RSState      analyzer.RSStateResult      `json:"rsState"`
	Storage      analyzer.StorageResult      `json:"storage"`
	Transactions analyzer.TransactionResult  `json:"transactions"`
	Errors       analyzer.ErrorResult        `json:"errors"`
}

// WriteJSON serializes the analysis results as pretty-printed JSON to the writer.
func WriteJSON(w io.Writer, results analyzer.Results) error {
	out := jsonOutput{
		General:      results.General,
		SlowQueries:  results.SlowQueries,
		TableScans:   results.TableScans,
		Connections:  results.Connections,
		Clients:      results.Clients,
		Distinct:     results.Distinct,
		RSState:      results.RSState,
		Storage:      results.Storage,
		Transactions: results.Transactions,
		Errors:       results.Errors,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

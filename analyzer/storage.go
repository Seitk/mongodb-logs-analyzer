package analyzer

import (
	"sort"

	"github.com/Seitk/mongodb-logs-analyzer/parser"
)

// StorageNamespace holds per-namespace storage I/O stats.
type StorageNamespace struct {
	Namespace         string
	TotalBytesRead    int64
	TotalBytesWritten int64
	TotalTimeReadUs   int64
	TotalTimeWriteUs  int64
	OpCount           int
	MeanBytesRead     int64
	MeanBytesWritten  int64
}

// StorageResult holds all storage analysis results.
type StorageResult struct {
	Namespaces []StorageNamespace
}

// StorageAccumulator tracks per-namespace storage I/O.
type StorageAccumulator struct {
	namespaces map[string]*StorageNamespace
}

// NewStorageAccumulator creates a new StorageAccumulator.
func NewStorageAccumulator() *StorageAccumulator {
	return &StorageAccumulator{
		namespaces: make(map[string]*StorageNamespace),
	}
}

// Process processes a slow query entry for storage stats.
func (s *StorageAccumulator) Process(entry parser.LogEntry) {
	ns := entry.AttrString("ns")
	if ns == "" {
		return
	}

	storageMap := entry.AttrMap("storage")
	if storageMap == nil {
		return
	}

	dataMap, ok := storageMap["data"].(map[string]interface{})
	if !ok {
		return
	}

	nsStats, exists := s.namespaces[ns]
	if !exists {
		nsStats = &StorageNamespace{Namespace: ns}
		s.namespaces[ns] = nsStats
	}

	nsStats.OpCount++

	if v, ok := dataMap["bytesRead"].(float64); ok {
		nsStats.TotalBytesRead += int64(v)
	}
	if v, ok := dataMap["bytesWritten"].(float64); ok {
		nsStats.TotalBytesWritten += int64(v)
	}
	if v, ok := dataMap["timeReadingMicros"].(float64); ok {
		nsStats.TotalTimeReadUs += int64(v)
	}
	if v, ok := dataMap["timeWritingMicros"].(float64); ok {
		nsStats.TotalTimeWriteUs += int64(v)
	}
}

// Result returns the storage results sorted by TotalBytesRead descending.
func (s *StorageAccumulator) Result() StorageResult {
	namespaces := make([]StorageNamespace, 0, len(s.namespaces))
	for _, ns := range s.namespaces {
		if ns.OpCount > 0 {
			ns.MeanBytesRead = ns.TotalBytesRead / int64(ns.OpCount)
			ns.MeanBytesWritten = ns.TotalBytesWritten / int64(ns.OpCount)
		}
		namespaces = append(namespaces, *ns)
	}
	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].TotalBytesRead > namespaces[j].TotalBytesRead
	})
	return StorageResult{Namespaces: namespaces}
}

package parser

import (
	"bufio"
	"fmt"
	"os"
)

const (
	scannerInitialBuf = 64 * 1024  // 64 KB
	scannerMaxBuf     = 1024 * 1024 // 1 MB
)

// ScanFile streams a MongoDB log file line-by-line, parsing each line
// into a LogEntry and calling the callback for each successfully parsed entry.
// Malformed lines are silently skipped.
func ScanFile(path string, callback func(LogEntry)) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("scan file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, scannerInitialBuf)
	scanner.Buffer(buf, scannerMaxBuf)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		entry, err := ParseLogEntry(line)
		if err != nil {
			// Skip malformed lines
			continue
		}

		callback(entry)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan file: %w", err)
	}

	return nil
}

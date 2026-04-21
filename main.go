package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anthropics/mla/analyzer"
	"github.com/anthropics/mla/report"
)

func main() {
	// Define flags
	format := flag.String("format", "html", "Output format: html or json")
	output := flag.String("o", "", "Output file path (default: <logname>_report.<format>)")
	outputLong := flag.String("output", "", "Output file path (default: <logname>_report.<format>)")
	aiFlag := flag.Bool("ai", false, "Enable AI analysis")
	repoPath := flag.String("repo", "", "Repository path for code context in AI analysis")
	aiCmd := flag.String("ai-cmd", "claude -p", "AI command to execute")
	slowMS := flag.Int("slow", 100, "Slow query threshold in milliseconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mla [flags] <logfile>\n\nAnalyze MongoDB log files and generate reports.\n\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Validate positional argument
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: log file path is required\n\n")
		flag.Usage()
		os.Exit(1)
	}
	logFile := flag.Arg(0)

	// Resolve output flag (short or long form)
	outPath := *output
	if outPath == "" {
		outPath = *outputLong
	}

	// Validate format
	*format = strings.ToLower(*format)
	if *format != "html" && *format != "json" {
		fmt.Fprintf(os.Stderr, "Error: invalid format %q, must be html or json\n", *format)
		os.Exit(1)
	}

	// Validate log file exists
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: log file not found: %s\n", logFile)
		os.Exit(1)
	}

	// Run analysis
	fmt.Fprintf(os.Stderr, "Analyzing %s (slow threshold: %dms)...\n", logFile, *slowMS)

	a := analyzer.New(*slowMS)
	results, err := a.Run(logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: analysis failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Analysis complete: %d lines processed\n", results.General.TotalLines)

	// Generate output
	switch *format {
	case "json":
		if outPath == "" {
			// Write to stdout
			if err := report.WriteJSON(os.Stdout, results); err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to write JSON: %v\n", err)
				os.Exit(1)
			}
		} else {
			f, err := os.Create(outPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to create output file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			if err := report.WriteJSON(f, results); err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to write JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "JSON report written to %s\n", outPath)
		}

	case "html":
		// Optionally run AI analysis
		var aiAnalysis string
		if *aiFlag {
			fmt.Fprintf(os.Stderr, "Running AI analysis...\n")
			aiAnalysis, err = report.RunAISynthesis(results, *aiCmd, *repoPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: AI analysis failed: %v\n", err)
				// Continue without AI analysis
			} else {
				fmt.Fprintf(os.Stderr, "AI analysis complete\n")
			}
		}

		// Default output filename
		if outPath == "" {
			base := filepath.Base(logFile)
			ext := filepath.Ext(base)
			name := strings.TrimSuffix(base, ext)
			outPath = name + "_report.html"
		}

		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		if err := report.WriteHTML(f, results, aiAnalysis); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to write HTML: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "HTML report written to %s\n", outPath)
	}
}

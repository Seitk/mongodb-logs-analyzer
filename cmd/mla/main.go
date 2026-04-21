package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Seitk/mongodb-logs-analyzer/internal/analyzer"
	"github.com/Seitk/mongodb-logs-analyzer/internal/atlas"
	"github.com/Seitk/mongodb-logs-analyzer/internal/datadog"
	"github.com/Seitk/mongodb-logs-analyzer/internal/report"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "download" {
		runDownload(os.Args[2:])
		return
	}
	runAnalyze()
}

func runAnalyze() {
	format := flag.String("format", "html", "Output format: html or json")
	output := flag.String("o", "", "Output file path (default: <logname>_report.<format>)")
	outputLong := flag.String("output", "", "Output file path (default: <logname>_report.<format>)")
	aiFlag := flag.Bool("ai", false, "Enable AI analysis")
	repoPath := flag.String("repo", "", "Repository path for code context in AI analysis")
	aiCmd := flag.String("ai-cmd", "claude -p", "AI command to execute")
	slowMS := flag.Int("slow", 100, "Slow query threshold in milliseconds")
	ddFlag := flag.Bool("datadog", false, "Send metrics to Datadog (requires DD_API_KEY)")
	ddAPIKey := flag.String("dd-api-key", "", "Datadog API key (or set DD_API_KEY)")
	ddSite := flag.String("dd-site", "", "Datadog site (or set DD_SITE, default: datadoghq.com)")
	ddPrefix := flag.String("dd-prefix", "", "Datadog metric prefix (default: mongodb)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mla [flags] <logfile>\n       mla download [flags]\n\nAnalyze MongoDB log files and generate reports.\n\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: log file path is required\n\n")
		flag.Usage()
		os.Exit(1)
	}
	logFile := flag.Arg(0)

	outPath := *output
	if outPath == "" {
		outPath = *outputLong
	}

	*format = strings.ToLower(*format)
	if *format != "html" && *format != "json" {
		fmt.Fprintf(os.Stderr, "Error: invalid format %q, must be html or json\n", *format)
		os.Exit(1)
	}

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: log file not found: %s\n", logFile)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Analyzing %s (slow threshold: %dms)...\n", logFile, *slowMS)

	a := analyzer.New(*slowMS)
	results, err := a.Run(logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: analysis failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Analysis complete: %d lines processed\n", results.General.TotalLines)

	// Send metrics to Datadog if requested
	if *ddFlag {
		apiKey := *ddAPIKey
		if apiKey == "" {
			apiKey = os.Getenv("DD_API_KEY")
		}
		site := *ddSite
		if site == "" {
			site = os.Getenv("DD_SITE")
		}
		if apiKey == "" {
			fmt.Fprintf(os.Stderr, "Error: -datadog requires DD_API_KEY env var or -dd-api-key flag\n")
			os.Exit(1)
		}

		ddClient := datadog.NewClient(apiKey, site, *ddPrefix)
		fmt.Fprintf(os.Stderr, "Sending metrics to Datadog (%s)...\n", ddClient.Site)
		if err := ddClient.SubmitMetrics(results); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Datadog submission failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Metrics sent to Datadog\n")
		}
	}

	switch *format {
	case "json":
		if outPath == "" {
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
		var aiAnalysis string
		if *aiFlag {
			fmt.Fprintf(os.Stderr, "Running AI analysis...\n")
			aiAnalysis, err = report.RunAISynthesis(results, *aiCmd, *repoPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: AI analysis failed: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "AI analysis complete\n")
			}
		}

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

func runDownload(args []string) {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	projectID := fs.String("project", "", "Atlas project/group ID")
	hostname := fs.String("host", "", "Hostname to download logs from")
	logName := fs.String("log", "mongodb", "Log name: mongodb, mongos, mongodb-audit-log, mongos-audit-log")
	outDir := fs.String("o", ".", "Output directory for downloaded logs")
	startStr := fs.String("start", "", "Start time (ISO 8601, default: 24h ago)")
	endStr := fs.String("end", "", "End time (ISO 8601, default: now)")
	apiKey := fs.String("api-key", "", "Atlas public API key (or set ATLAS_PUBLIC_KEY)")
	apiSecret := fs.String("api-secret", "", "Atlas private API key (or set ATLAS_PRIVATE_KEY)")
	listProjects := fs.Bool("list-projects", false, "List available Atlas projects")
	listHosts := fs.Bool("list-hosts", false, "List hosts in a project")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mla download [flags]\n\nDownload MongoDB logs from Atlas.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  mla download -list-projects\n")
		fmt.Fprintf(os.Stderr, "  mla download -project <id> -list-hosts\n")
		fmt.Fprintf(os.Stderr, "  mla download -project <id> -host <hostname> -o logs/\n")
	}

	fs.Parse(args)

	pubKey := *apiKey
	if pubKey == "" {
		pubKey = os.Getenv("ATLAS_PUBLIC_KEY")
	}
	privKey := *apiSecret
	if privKey == "" {
		privKey = os.Getenv("ATLAS_PRIVATE_KEY")
	}

	if pubKey == "" || privKey == "" {
		fmt.Fprintf(os.Stderr, "Error: Atlas API credentials required.\n")
		fmt.Fprintf(os.Stderr, "Set ATLAS_PUBLIC_KEY and ATLAS_PRIVATE_KEY environment variables,\n")
		fmt.Fprintf(os.Stderr, "or use -api-key and -api-secret flags.\n")
		os.Exit(1)
	}

	client := atlas.NewClient(pubKey, privKey)

	if *listProjects {
		projects, err := client.ListProjects()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Found %d projects:\n", len(projects))
		for _, p := range projects {
			fmt.Printf("  %-28s %s\n", p.ID, p.Name)
		}
		return
	}

	if *listHosts {
		if *projectID == "" {
			fmt.Fprintf(os.Stderr, "Error: -project is required with -list-hosts\n")
			os.Exit(1)
		}
		procs, err := client.ListProcesses(*projectID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Found %d hosts:\n", len(procs))
		for _, p := range procs {
			fmt.Printf("  %-50s %-6d %s\n", p.Hostname, p.Port, p.TypeName)
		}
		return
	}

	// Download logs
	if *projectID == "" || *hostname == "" {
		fmt.Fprintf(os.Stderr, "Error: -project and -host are required for log download\n\n")
		fs.Usage()
		os.Exit(1)
	}

	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour)
	end := now

	if *startStr != "" {
		t, err := time.Parse(time.RFC3339, *startStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -start time: %v\n", err)
			os.Exit(1)
		}
		start = t
	}
	if *endStr != "" {
		t, err := time.Parse(time.RFC3339, *endStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -end time: %v\n", err)
			os.Exit(1)
		}
		end = t
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: create output directory: %v\n", err)
		os.Exit(1)
	}

	outFile := filepath.Join(*outDir, fmt.Sprintf("%s_%s_%s_%s.log",
		sanitizeFilename(*hostname),
		start.Format("2006-01-02T15-04-05"),
		end.Format("2006-01-02T15-04-05"),
		strings.ToUpper(*logName),
	))

	fmt.Fprintf(os.Stderr, "Downloading %s logs from %s...\n", *logName, *hostname)
	fmt.Fprintf(os.Stderr, "  Time range: %s to %s\n", start.Format(time.RFC3339), end.Format(time.RFC3339))

	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: create output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := client.DownloadLog(*projectID, *hostname, *logName, start, end, f); err != nil {
		os.Remove(outFile)
		fmt.Fprintf(os.Stderr, "Error: download failed: %v\n", err)
		os.Exit(1)
	}

	info, _ := f.Stat()
	fmt.Fprintf(os.Stderr, "Downloaded to %s (%s)\n", outFile, formatSize(info.Size()))
}

func sanitizeFilename(s string) string {
	r := strings.NewReplacer(":", "_", "/", "_", "\\", "_")
	return r.Replace(s)
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), []string{"KB", "MB", "GB"}[exp])
}

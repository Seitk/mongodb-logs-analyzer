package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Seitk/mongodb-logs-analyzer/analyzer"
)

// RunAISynthesis generates an AI analysis of the results by piping a prompt
// to the specified AI command (e.g., "claude -p").
func RunAISynthesis(results analyzer.Results, aiCmd string, repoPath string) (string, error) {
	// Marshal results to JSON for the AI prompt
	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal results for AI: %w", err)
	}

	// Build code context if repoPath is set
	var codeContext string
	if repoPath != "" {
		codeContext = scanRepoForCollections(results, repoPath)
	}

	// Build the prompt
	var prompt strings.Builder
	prompt.WriteString(`You are a MongoDB performance expert analyzing production log data. Provide a structured analysis using ONLY these HTML elements: <h3>, <p>, <ul>, <li>, <strong>, <code>, <span>. Do NOT use markdown.

Structure your response in exactly these sections:

<h3>Health Summary</h3>
<p>3-5 sentence overview of database health. Be specific with numbers.</p>

<h3>Critical Issues</h3>
For each issue (top 3-5), use this exact format:
<div class="ai-issue ai-severity-high">
  <h4>Issue Title</h4>
  <p><strong>Impact:</strong> One sentence on what this means for production.</p>
  <p><strong>Evidence:</strong> Specific metrics from the data (durations, counts, ratios).</p>
  <p><strong>Fix:</strong> Exact command or code change. Use <code> tags for commands.</p>
</div>

Use class "ai-severity-high" for critical, "ai-severity-medium" for moderate, "ai-severity-low" for minor.

<h3>Quick Wins</h3>
<ul><li>Actions that can be done in under 1 hour, with specific commands.</li></ul>

<h3>Longer-Term Improvements</h3>
<ul><li>Architecture or design changes that need planning.</li></ul>

Important: Be concise. Use actual numbers from the data. Every recommendation must include a specific command, index creation, or config change — no vague advice.

`)
	prompt.WriteString("Analysis Results:\n")
	prompt.Write(resultsJSON)

	if codeContext != "" {
		prompt.WriteString("\n\nCode Context (files referencing collections from slow queries):\n")
		prompt.WriteString(codeContext)
	}

	// Parse the AI command
	parts := strings.Fields(aiCmd)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty AI command")
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin = strings.NewReader(prompt.String())

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("AI command failed: %w\nstderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// scanRepoForCollections searches the repository for references to collection
// names found in slow query namespaces.
func scanRepoForCollections(results analyzer.Results, repoPath string) string {
	// Extract unique collection names from slow query namespaces
	collections := make(map[string]struct{})
	for _, grp := range results.SlowQueries.Groups {
		ns := grp.Namespace
		// Namespace format: "db.collection"
		parts := strings.SplitN(ns, ".", 2)
		if len(parts) == 2 && parts[1] != "" {
			collections[parts[1]] = struct{}{}
		}
	}

	if len(collections) == 0 {
		return ""
	}

	var context strings.Builder
	extensions := []string{".js", ".ts", ".go", ".py"}

	for collection := range collections {
		matches := grepRepo(repoPath, collection, extensions)
		if len(matches) > 0 {
			context.WriteString(fmt.Sprintf("\nCollection %q referenced in:\n", collection))
			limit := 10
			if len(matches) < limit {
				limit = len(matches)
			}
			for _, m := range matches[:limit] {
				context.WriteString(fmt.Sprintf("  %s\n", m))
			}
			if len(matches) > 10 {
				context.WriteString(fmt.Sprintf("  ... and %d more matches\n", len(matches)-10))
			}
		}
	}

	return context.String()
}

// grepRepo searches for a pattern in files with the given extensions under root.
func grepRepo(root string, pattern string, extensions []string) []string {
	var matches []string

	for _, ext := range extensions {
		globPattern := filepath.Join(root, "**", "*"+ext)
		files, err := filepath.Glob(globPattern)
		if err != nil {
			continue
		}

		// Also try one level deep
		shallowPattern := filepath.Join(root, "*"+ext)
		shallowFiles, err := filepath.Glob(shallowPattern)
		if err == nil {
			files = append(files, shallowFiles...)
		}

		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if strings.Contains(line, pattern) {
					rel, _ := filepath.Rel(root, f)
					if rel == "" {
						rel = f
					}
					matches = append(matches, fmt.Sprintf("%s:%d: %s", rel, i+1, strings.TrimSpace(line)))
				}
			}
		}
	}

	return matches
}

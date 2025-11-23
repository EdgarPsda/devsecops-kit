package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SemgrepOutput represents the JSON output from Semgrep
type SemgrepOutput struct {
	Results []struct {
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
		Message   string `json:"message"`
		Severity  string `json:"severity"`
		RuleID    string `json:"check_id"`
		Extra     struct {
			Severity string `json:"severity"`
			Metadata struct {
				CWE []string `json:"cwe"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"errors"`
}

// runSemgrep executes a Semgrep scan
func (o *Orchestrator) runSemgrep() (*ScanResult, error) {
	result := &ScanResult{
		Tool:     "semgrep",
		Findings: []Finding{},
		Summary:  FindingSummary{},
	}

	// Check if Semgrep is installed
	if _, err := exec.LookPath("semgrep"); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("semgrep not installed. Install with: pip install semgrep or brew install semgrep")
		return result, result.Error
	}

	// Build Semgrep command
	cmd := exec.Command("semgrep", "--config", "p/ci", "--json")

	// Add exclude paths
	for _, path := range o.options.ExcludePaths {
		cmd.Args = append(cmd.Args, "--exclude", path)
	}

	// Set working directory
	cmd.Dir = o.projectDir

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Semgrep exits with code 1 if findings are detected, which is not a real error
		// Only fail if the output isn't JSON or contains parsing errors
		if !strings.Contains(string(output), "\"results\"") {
			result.Status = "error"
			result.Error = fmt.Errorf("semgrep execution failed: %w", err)
			return result, result.Error
		}
	}

	// Parse JSON output
	var semgrepOut SemgrepOutput
	if err := json.Unmarshal(output, &semgrepOut); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("failed to parse semgrep output: %w", err)
		return result, result.Error
	}

	// Convert to findings
	for _, sr := range semgrepOut.Results {
		severity := sr.Extra.Severity
		if severity == "" {
			severity = sr.Severity
		}

		// Normalize severity
		normSeverity := normalizeSeverity(severity)

		finding := Finding{
			File:      sr.Path,
			Line:      sr.StartLine,
			Severity:  normSeverity,
			Message:   sr.Message,
			RuleID:    sr.RuleID,
			Tool:      "semgrep",
		}

		result.Findings = append(result.Findings, finding)

		// Update summary counts
		result.Summary.Total++
		switch normSeverity {
		case "CRITICAL":
			result.Summary.Critical++
		case "HIGH":
			result.Summary.High++
		case "MEDIUM":
			result.Summary.Medium++
		case "LOW":
			result.Summary.Low++
		}
	}

	if len(semgrepOut.Errors) > 0 {
		// Log errors but continue
		if o.options.Verbose {
			for _, e := range semgrepOut.Errors {
				fmt.Fprintf(os.Stderr, "⚠️  Semgrep warning: %s\n", e.Message)
			}
		}
	}

	if result.Summary.Total == 0 {
		result.Status = "success"
	} else {
		result.Status = "success"
	}

	return result, nil
}

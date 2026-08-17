package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/edgarpsda/devsecops-kit/internal/tools"
)

// SemgrepOutput represents the JSON output from Semgrep
type SemgrepOutput struct {
	Results []struct {
		Path      string          `json:"path"`
		Start     SemgrepPosition `json:"start"`
		End       SemgrepPosition `json:"end"`
		StartLine int             `json:"start_line"`
		EndLine   int             `json:"end_line"`
		Message   string          `json:"message"`
		Severity  string          `json:"severity"`
		RuleID    string          `json:"check_id"`
		Extra     struct {
			Message  string                 `json:"message"`
			Severity string                 `json:"severity"`
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"errors"`
}

// SemgrepPosition represents a Semgrep JSON source position.
type SemgrepPosition struct {
	Line   int `json:"line"`
	Column int `json:"col"`
	Offset int `json:"offset,omitempty"`
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
	cmd := tools.Command("semgrep", "scan", "--config", "auto", "--json", "--quiet")

	// Add exclude paths
	for _, path := range o.options.ExcludePaths {
		cmd.Args = append(cmd.Args, "--exclude", path)
	}

	// Set working directory
	cmd.Dir = o.projectDir

	// Capture stdout and stderr separately so only stdout is parsed as JSON.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Parse JSON output
	err := cmd.Run()
	jsonOutput, parseErr := semgrepJSONPayload(stdout.Bytes())
	if parseErr != nil {
		result.Status = "error"
		if err != nil {
			result.Error = fmt.Errorf("semgrep execution failed: %w\n\nunable to parse Semgrep JSON output: %v\n\nstdout:\n%s\n\nstderr:\n%s", err, parseErr, stdout.String(), stderr.String())
		} else {
			result.Error = fmt.Errorf("unable to parse Semgrep JSON output: %w\n\nstdout:\n%s\n\nstderr:\n%s", parseErr, stdout.String(), stderr.String())
		}
		return result, result.Error
	}

	var semgrepOut SemgrepOutput
	if err := json.Unmarshal(jsonOutput, &semgrepOut); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("unable to parse Semgrep JSON output: %w\n\nstdout:\n%s\n\nstderr:\n%s", err, stdout.String(), stderr.String())
		return result, result.Error
	}

	result.Findings = semgrepFindings(semgrepOut)
	result.Summary = summarizeFindings(result.Findings)

	if o.options.Verbose {
		fmt.Fprintf(os.Stderr, "Semgrep JSON results: %d\n", len(semgrepOut.Results))
		fmt.Fprintf(os.Stderr, "Semgrep findings converted: %d\n", len(result.Findings))
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

func semgrepFindings(output SemgrepOutput) []Finding {
	var findings []Finding

	for _, sr := range output.Results {
		line := sr.Start.Line
		if line == 0 {
			line = sr.StartLine
		}

		column := sr.Start.Column
		message := sr.Extra.Message
		if message == "" {
			message = sr.Message
		}

		severity := sr.Extra.Severity
		if severity == "" {
			severity = sr.Severity
		}

		findings = append(findings, Finding{
			File:     sr.Path,
			Line:     line,
			Column:   column,
			Severity: normalizeSeverity(severity),
			Blocking: semgrepBlocking(sr.Extra.Metadata),
			Message:  message,
			RuleID:   sr.RuleID,
			Tool:     "semgrep",
		})
	}

	return findings
}

func semgrepBlocking(metadata map[string]interface{}) bool {
	for _, key := range []string{"blocking", "block", "devsecops_blocking"} {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		if boolValue(value) {
			return true
		}
	}
	return false
}

func boolValue(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || v == "1"
	default:
		return false
	}
}

func semgrepJSONPayload(output []byte) ([]byte, error) {
	if len(bytes.TrimSpace(output)) == 0 {
		return nil, fmt.Errorf("stdout is empty")
	}

	for i, b := range output {
		if b != '{' {
			continue
		}

		decoder := json.NewDecoder(bytes.NewReader(output[i:]))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			continue
		}
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}

		return raw, nil
	}

	return nil, fmt.Errorf("no valid JSON object found in stdout")
}

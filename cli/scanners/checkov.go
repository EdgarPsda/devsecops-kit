package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// checkovOutput represents the JSON output from a Checkov scan
type checkovOutput struct {
	Results struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
	Summary struct {
		Failed int `json:"failed"`
		Passed int `json:"passed"`
	} `json:"summary"`
}

type checkovCheck struct {
	CheckID       string   `json:"check_id"`
	CheckName     string   `json:"check_name"`
	FilePath      string   `json:"file_path"`
	FileLineRange []int    `json:"file_line_range"`
	Resource      string   `json:"resource"`
	Severity      string   `json:"severity"` // HIGH, MEDIUM, LOW (populated in newer versions)
}

// runCheckov executes Checkov IaC scanning
func (o *Orchestrator) runCheckov() (*ScanResult, error) {
	result := &ScanResult{
		Tool:     "checkov",
		Findings: []Finding{},
		Summary:  FindingSummary{},
	}

	if _, err := exec.LookPath("checkov"); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("checkov not installed: run 'pip install checkov'")
		return result, result.Error
	}

	args := []string{"-d", ".", "--output", "json", "--compact", "--quiet"}
	for _, p := range o.options.ExcludePaths {
		args = append(args, "--skip-path", p)
	}

	cmd := exec.Command("checkov", args...)
	cmd.Dir = o.projectDir

	output, err := cmd.Output()
	// Checkov exits with code 1 when it finds violations — that's normal
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				result.Status = "error"
				result.Error = fmt.Errorf("checkov exited with code %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
				return result, result.Error
			}
		}
	}

	if len(output) == 0 {
		result.Status = "success"
		return result, nil
	}

	// Checkov may output multiple JSON objects (one per framework) — parse the first valid one
	// or handle an array of results
	findings, err := parseCheckovOutput(output)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("failed to parse checkov output: %w", err)
		return result, result.Error
	}

	result.Findings = findings
	result.Summary = summarizeFindings(findings)
	result.Status = "success"
	return result, nil
}

// parseCheckovOutput handles both single-object and array Checkov JSON output
func parseCheckovOutput(data []byte) ([]Finding, error) {
	var findings []Finding

	// Try single object first
	var single checkovOutput
	if err := json.Unmarshal(data, &single); err == nil {
		findings = append(findings, extractCheckovFindings(single)...)
		return findings, nil
	}

	// Try array of objects (multiple frameworks scanned)
	var multi []checkovOutput
	if err := json.Unmarshal(data, &multi); err == nil {
		for _, out := range multi {
			findings = append(findings, extractCheckovFindings(out)...)
		}
		return findings, nil
	}

	return nil, fmt.Errorf("unrecognised checkov JSON structure")
}

func extractCheckovFindings(out checkovOutput) []Finding {
	var findings []Finding

	for _, check := range out.Results.FailedChecks {
		line := 0
		if len(check.FileLineRange) > 0 {
			line = check.FileLineRange[0]
		}

		severity := mapCheckovSeverity(check.CheckID, check.Severity)
		msg := check.CheckName
		if check.Resource != "" {
			msg = fmt.Sprintf("%s [%s]", check.CheckName, check.Resource)
		}

		findings = append(findings, Finding{
			File:     check.FilePath,
			Line:     line,
			Severity: severity,
			Message:  msg,
			RuleID:   check.CheckID,
			Tool:     "checkov",
		})
	}

	return findings
}

// mapCheckovSeverity maps Checkov check IDs to severities.
// Newer Checkov versions populate the Severity field directly;
// for older versions we fall back to check-ID prefix heuristics.
func mapCheckovSeverity(checkID, rawSeverity string) string {
	if raw := strings.ToUpper(rawSeverity); raw == "CRITICAL" || raw == "HIGH" || raw == "MEDIUM" || raw == "LOW" {
		return raw
	}

	// Heuristic fallback based on check-ID prefix
	upper := strings.ToUpper(checkID)
	switch {
	case strings.HasPrefix(upper, "CKV2_"):
		return "HIGH"
	case strings.HasPrefix(upper, "CKV_K8S_"):
		return "MEDIUM"
	case strings.HasPrefix(upper, "CKV_AWS_"), strings.HasPrefix(upper, "CKV_AZURE_"), strings.HasPrefix(upper, "CKV_GCP_"):
		return "HIGH"
	default:
		return "MEDIUM"
	}
}

// summarizeFindings builds a FindingSummary from a slice of findings
func summarizeFindings(findings []Finding) FindingSummary {
	s := FindingSummary{Total: len(findings)}
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		case "LOW":
			s.Low++
		}
	}
	return s
}

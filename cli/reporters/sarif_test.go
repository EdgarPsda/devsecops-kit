package reporters

import (
	"encoding/json"
	"testing"

	"github.com/edgarpsda/devsecops-kit/cli/scanners"
)

func TestSARIFReporter_Generate_WithFindings(t *testing.T) {
	report := &scanners.ScanReport{
		Status:        "FAIL",
		BlockingCount: 2,
		AllFindings: []scanners.Finding{
			{
				File:     "src/main.go",
				Line:     42,
				Column:   10,
				Severity: "HIGH",
				Message:  "Hardcoded secret detected",
				RuleID:   "generic-api-key",
				Tool:     "gitleaks",
			},
			{
				File:     "src/handler.go",
				Line:     15,
				Severity: "CRITICAL",
				Message:  "SQL injection vulnerability",
				RuleID:   "go.lang.security.audit.sqli",
				Tool:     "semgrep",
			},
			{
				File:     "go.mod",
				Severity: "MEDIUM",
				Message:  "CVE-2024-1234: Buffer overflow in lib",
				RuleID:   "CVE-2024-1234",
				Tool:     "trivy",
			},
		},
	}

	reporter := NewSARIFReporter(report)
	data, err := reporter.Generate()
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	// Parse and validate structure
	var sarifReport SARIFReport
	if err := json.Unmarshal(data, &sarifReport); err != nil {
		t.Fatalf("failed to parse SARIF output: %v", err)
	}

	if sarifReport.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarifReport.Version)
	}

	// Should have runs for each tool with findings
	if len(sarifReport.Runs) == 0 {
		t.Fatal("expected at least one run")
	}

	// Count total results across all runs
	totalResults := 0
	for _, run := range sarifReport.Runs {
		totalResults += len(run.Results)
	}

	if totalResults != 3 {
		t.Errorf("expected 3 total results, got %d", totalResults)
	}
}

func TestSARIFReporter_Generate_NoFindings(t *testing.T) {
	report := &scanners.ScanReport{
		Status:      "PASS",
		AllFindings: []scanners.Finding{},
	}

	reporter := NewSARIFReporter(report)
	data, err := reporter.Generate()
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var sarifReport SARIFReport
	if err := json.Unmarshal(data, &sarifReport); err != nil {
		t.Fatalf("failed to parse SARIF output: %v", err)
	}

	if len(sarifReport.Runs) != 1 {
		t.Errorf("expected 1 empty run, got %d", len(sarifReport.Runs))
	}

	if len(sarifReport.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(sarifReport.Runs[0].Results))
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"UNKNOWN", "warning"},
	}

	for _, tt := range tests {
		got := severityToSARIFLevel(tt.severity)
		if got != tt.expected {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tt.severity, got, tt.expected)
		}
	}
}

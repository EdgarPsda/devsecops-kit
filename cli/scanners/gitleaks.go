package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// GitLeaksOutput represents the JSON output from Gitleaks
type GitLeaksOutput struct {
	Leaks []struct {
		File      string `json:"File"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
		Match     string `json:"Match"`
		Secret    string `json:"Secret"`
		RuleID    string `json:"RuleID"`
		Author    string `json:"Author"`
		Date      string `json:"Date"`
		Message   string `json:"Message"`
	} `json:"leaks"`
}

// runGitleaks executes a Gitleaks scan
func (o *Orchestrator) runGitleaks() (*ScanResult, error) {
	result := &ScanResult{
		Tool:     "gitleaks",
		Findings: []Finding{},
		Summary:  FindingSummary{},
	}

	// Check if Gitleaks is installed
	if _, err := exec.LookPath("gitleaks"); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("gitleaks not installed. Install with: brew install gitleaks or go install github.com/gitleaks/gitleaks/v10@latest")
		return result, result.Error
	}

	// Build Gitleaks command
	cmd := exec.Command("gitleaks", "detect", "--report-format", "json", "--exit-code", "0")

	// Add exclude paths via config file if provided
	configPath := ""
	if len(o.options.ExcludePaths) > 0 {
		// Create temporary gitleaks config with exclusions
		configPath = o.projectDir + "/.gitleaks.toml"
		configContent := buildGitleaksConfig(o.options.ExcludePaths)
		if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
			result.Status = "error"
			result.Error = fmt.Errorf("failed to create gitleaks config: %w", err)
			return result, result.Error
		}
		defer os.Remove(configPath)
		cmd.Args = append(cmd.Args, "--config", configPath)
	}

	// Set working directory
	cmd.Dir = o.projectDir

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Gitleaks exits with code 0 regardless (we set --exit-code 0)
		// Only fail if output parsing fails
		if len(output) == 0 {
			result.Status = "error"
			result.Error = fmt.Errorf("gitleaks execution failed: %w", err)
			return result, result.Error
		}
	}

	// Parse JSON output (even empty result is valid JSON)
	var gitleaksOut GitLeaksOutput
	if err := json.Unmarshal(output, &gitleaksOut); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("failed to parse gitleaks output: %w (output: %s)", err, string(output))
		return result, result.Error
	}

	// Convert leaks to findings
	// All secrets are CRITICAL severity
	for _, leak := range gitleaksOut.Leaks {
		finding := Finding{
			File:     leak.File,
			Line:     leak.StartLine,
			Severity: "CRITICAL",
			Blocking: true,
			Message:  fmt.Sprintf("Secret detected: %s", leak.RuleID),
			RuleID:   leak.RuleID,
			Tool:     "gitleaks",
		}

		result.Findings = append(result.Findings, finding)
		result.Summary.Total++
		result.Summary.Critical++
	}

	result.Status = "success"
	return result, nil
}

// buildGitleaksConfig creates a Gitleaks config file with path exclusions
func buildGitleaksConfig(excludePaths []string) string {
	// Build the allowlist section
	allowlistPaths := "paths = ["
	for _, path := range excludePaths {
		allowlistPaths += fmt.Sprintf("\n  \"%s\",", path)
	}
	allowlistPaths += "\n]"

	config := fmt.Sprintf(`[allowlist]
%s
`, allowlistPaths)

	return config
}

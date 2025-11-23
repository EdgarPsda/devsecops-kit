package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// TrivyOutput represents the JSON output from Trivy
type TrivyOutput struct {
	Results []struct {
		Target     string `json:"Target"`
		Class      string `json:"Class"`
		Misconfigs []struct {
			Title       string `json:"Title"`
			Description string `json:"Description"`
			Severity    string `json:"Severity"`
			StartLine   int    `json:"StartLine"`
			EndLine     int    `json:"EndLine"`
		} `json:"Misconfigs"`
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Title           string `json:"Title"`
			Description     string `json:"Description"`
			Severity        string `json:"Severity"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion    string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
	ArtifactName string `json:"ArtifactName"`
}

// runTrivy executes Trivy scans (filesystem and optionally image)
func (o *Orchestrator) runTrivy() (*ScanResult, error) {
	result := &ScanResult{
		Tool:     "trivy",
		Findings: []Finding{},
		Summary:  FindingSummary{},
	}

	// Check if Trivy is installed
	if _, err := exec.LookPath("trivy"); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("trivy not installed. Install with: brew install trivy or visit https://github.com/aquasecurity/trivy")
		return result, result.Error
	}

	// Run filesystem scan
	fsFindings, err := o.runTrivyFilesystem()
	if err != nil {
		// Log error but continue to image scan if available
		fmt.Fprintf(os.Stderr, "⚠️  Trivy FS scan failed: %v\n", err)
	}
	result.Findings = append(result.Findings, fsFindings...)

	// Run image scan if Docker detected
	if o.options.EnableTrivyImage && len(o.options.DockerImages) > 0 {
		for _, image := range o.options.DockerImages {
			imageFindings, err := o.runTrivyImage(image)
			if err != nil {
				// Log error but continue
				fmt.Fprintf(os.Stderr, "⚠️  Trivy image scan failed for %s: %v\n", image, err)
				continue
			}
			result.Findings = append(result.Findings, imageFindings...)
		}
	}

	// Update summary counts
	for _, finding := range result.Findings {
		result.Summary.Total++
		switch finding.Severity {
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

	result.Status = "success"
	return result, nil
}

// runTrivyFilesystem performs a Trivy filesystem scan
func (o *Orchestrator) runTrivyFilesystem() ([]Finding, error) {
	var findings []Finding

	// Build Trivy command
	cmd := exec.Command("trivy", "fs", ".", "--format", "json")

	// Add severity filter
	cmd.Args = append(cmd.Args, "--severity", "HIGH,CRITICAL,MEDIUM,LOW")

	// Add skip-dirs for exclusions
	for _, path := range o.options.ExcludePaths {
		cmd.Args = append(cmd.Args, "--skip-dirs", path)
	}

	// Set working directory
	cmd.Dir = o.projectDir

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Trivy exits with code 0 if no vulnerabilities, code 1+ if found (we allow both)
		// Only fail if output parsing fails
		if len(output) == 0 || !strings.Contains(string(output), "Results") {
			return findings, fmt.Errorf("trivy execution failed: %w", err)
		}
	}

	// Extract JSON from output (Trivy may output warnings before JSON)
	jsonOutput := extractJSON(output)
	if len(jsonOutput) == 0 {
		// No JSON found, likely no vulnerabilities
		return findings, nil
	}

	// Parse JSON output
	var trivyOut TrivyOutput
	if err := json.Unmarshal(jsonOutput, &trivyOut); err != nil {
		return findings, fmt.Errorf("failed to parse trivy output: %w (output: %s)", err, string(jsonOutput[:min(len(jsonOutput), 200)]))
	}

	// Convert vulnerabilities to findings
	for _, scanResult := range trivyOut.Results {
		// Process vulnerabilities
		for _, vuln := range scanResult.Vulnerabilities {
			severity := normalizeSeverity(vuln.Severity)

			finding := Finding{
				File:     scanResult.Target,
				Severity: severity,
				Message:  fmt.Sprintf("%s: %s", vuln.VulnerabilityID, vuln.Title),
				RuleID:   vuln.VulnerabilityID,
				Tool:     "trivy",
			}

			findings = append(findings, finding)
		}

		// Process misconfigurations if present
		for _, misconfig := range scanResult.Misconfigs {
			severity := normalizeSeverity(misconfig.Severity)

			finding := Finding{
				File:     scanResult.Target,
				Line:     misconfig.StartLine,
				Severity: severity,
				Message:  fmt.Sprintf("%s: %s", misconfig.Title, misconfig.Description),
				RuleID:   misconfig.Title,
				Tool:     "trivy",
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// runTrivyImage performs a Trivy image scan
func (o *Orchestrator) runTrivyImage(image string) ([]Finding, error) {
	var findings []Finding

	// Build Trivy command
	cmd := exec.Command("trivy", "image", image, "--format", "json")

	// Add severity filter
	cmd.Args = append(cmd.Args, "--severity", "HIGH,CRITICAL,MEDIUM,LOW")

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Trivy exits with code 1 if vulnerabilities found, which is not an error
		// Only fail if output is empty or doesn't contain expected format
		if len(output) == 0 || !strings.Contains(string(output), "Results") {
			return findings, fmt.Errorf("trivy image execution failed: %w", err)
		}
	}

	// Extract JSON from output
	jsonOutput := extractJSON(output)
	if len(jsonOutput) == 0 {
		// No JSON found, likely no vulnerabilities
		return findings, nil
	}

	// Parse JSON output
	var trivyOut TrivyOutput
	if err := json.Unmarshal(jsonOutput, &trivyOut); err != nil {
		return findings, fmt.Errorf("failed to parse trivy image output: %w", err)
	}

	// Convert vulnerabilities to findings
	for _, scanResult := range trivyOut.Results {
		// Process vulnerabilities
		for _, vuln := range scanResult.Vulnerabilities {
			severity := normalizeSeverity(vuln.Severity)

			finding := Finding{
				File:     fmt.Sprintf("%s (image: %s)", scanResult.Target, image),
				Severity: severity,
				Message:  fmt.Sprintf("%s: %s", vuln.VulnerabilityID, vuln.Title),
				RuleID:   vuln.VulnerabilityID,
				Tool:     "trivy",
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// extractJSON finds and extracts the JSON portion from Trivy output
// Trivy may output warnings/status before JSON, so we find the first { and extract from there
func extractJSON(output []byte) []byte {
	// Find the first opening brace
	startIdx := bytes.IndexByte(output, '{')
	if startIdx == -1 {
		return nil
	}

	// Find the last closing brace
	endIdx := bytes.LastIndexByte(output, '}')
	if endIdx == -1 {
		return nil
	}

	return output[startIdx : endIdx+1]
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

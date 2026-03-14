package scanners

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// TrivyLicenseOutput represents the JSON output from Trivy license scan
type TrivyLicenseOutput struct {
	Results []struct {
		Target   string `json:"Target"`
		Class    string `json:"Class"`
		Licenses []struct {
			Severity   string `json:"Severity"`
			Category   string `json:"Category"`
			PkgName    string `json:"PkgName"`
			FilePath   string `json:"FilePath"`
			Name       string `json:"Name"`
			Confidence float64 `json:"Confidence"`
			Link       string `json:"Link"`
		} `json:"Licenses"`
	} `json:"Results"`
}

// LicenseConfig holds license scanning configuration
type LicenseConfig struct {
	Enabled bool
	Deny    []string
	Allow   []string
}

// runLicenseScan executes Trivy license scanning
func (o *Orchestrator) runLicenseScan() (*ScanResult, error) {
	result := &ScanResult{
		Tool:     "licenses",
		Findings: []Finding{},
		Summary:  FindingSummary{},
	}

	// Check if Trivy is installed
	if _, err := exec.LookPath("trivy"); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("trivy not installed (required for license scanning)")
		return result, result.Error
	}

	// Run trivy with license scanning
	cmd := exec.Command("trivy", "fs", ".", "--scanners", "license", "--format", "json")

	// Add skip-dirs for exclusions
	for _, path := range o.options.ExcludePaths {
		cmd.Args = append(cmd.Args, "--skip-dirs", path)
	}

	cmd.Dir = o.projectDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 || !strings.Contains(string(output), "Results") {
			result.Status = "error"
			result.Error = fmt.Errorf("trivy license scan failed: %w", err)
			return result, result.Error
		}
	}

	// Extract JSON
	jsonOutput := extractJSON(output)
	if len(jsonOutput) == 0 {
		result.Status = "success"
		return result, nil
	}

	// Parse output
	var licenseOut TrivyLicenseOutput
	if err := json.Unmarshal(jsonOutput, &licenseOut); err != nil {
		result.Status = "error"
		result.Error = fmt.Errorf("failed to parse trivy license output: %w", err)
		return result, result.Error
	}

	// Convert to findings, applying deny/allow lists
	for _, scanResult := range licenseOut.Results {
		for _, lic := range scanResult.Licenses {
			// Check if this license is a violation
			if !o.isLicenseViolation(lic.Name) {
				continue
			}

			severity := classifyLicenseSeverity(lic.Name, lic.Category)

			finding := Finding{
				File:     scanResult.Target,
				Severity: severity,
				Message:  fmt.Sprintf("License violation: %s uses %s license", lic.PkgName, lic.Name),
				RuleID:   fmt.Sprintf("license-%s", strings.ToLower(strings.ReplaceAll(lic.Name, " ", "-"))),
				Tool:     "licenses",
			}

			result.Findings = append(result.Findings, finding)
		}
	}

	// Update summary
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

// isLicenseViolation checks if a license should be flagged based on deny/allow lists
func (o *Orchestrator) isLicenseViolation(licenseName string) bool {
	lower := strings.ToLower(licenseName)

	// If deny list is configured, only flag denied licenses
	if len(o.options.LicenseConfig.Deny) > 0 {
		for _, denied := range o.options.LicenseConfig.Deny {
			if matchLicense(lower, strings.ToLower(denied)) {
				return true
			}
		}
		return false
	}

	// If allow list is configured, flag anything not allowed
	if len(o.options.LicenseConfig.Allow) > 0 {
		for _, allowed := range o.options.LicenseConfig.Allow {
			if matchLicense(lower, strings.ToLower(allowed)) {
				return false
			}
		}
		return true
	}

	// No lists configured: flag known copyleft licenses by default
	copyleftPrefixes := []string{"gpl", "agpl", "lgpl", "sspl", "eupl"}
	for _, prefix := range copyleftPrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}

	return false
}

// matchLicense checks if a license name matches a pattern (supports trailing wildcard)
func matchLicense(licenseName, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(licenseName, prefix)
	}
	return licenseName == pattern
}

// classifyLicenseSeverity assigns severity based on license type
func classifyLicenseSeverity(licenseName, category string) string {
	lower := strings.ToLower(licenseName)

	// Strong copyleft = HIGH
	if strings.Contains(lower, "agpl") || strings.Contains(lower, "sspl") {
		return "HIGH"
	}

	// Weak copyleft = LOW (check before GPL since LGPL contains "gpl")
	if strings.Contains(lower, "lgpl") || strings.Contains(lower, "mpl") {
		return "LOW"
	}

	// Copyleft = MEDIUM
	if strings.Contains(lower, "gpl") || strings.Contains(lower, "eupl") {
		return "MEDIUM"
	}

	// Restricted category from Trivy
	if strings.ToLower(category) == "restricted" {
		return "HIGH"
	}

	return "MEDIUM"
}

package reporters

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/edgarpsda/devsecops-kit/cli/scanners"
)

// SARIF schema version
const sarifVersion = "2.1.0"
const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

// SARIFReport represents the top-level SARIF document
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the primary analysis tool component
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a rule that produced a result
type SARIFRule struct {
	ID               string            `json:"id"`
	ShortDescription SARIFMessage      `json:"shortDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	DefaultConfig    *SARIFRuleConfig  `json:"defaultConfiguration,omitempty"`
}

// SARIFRuleConfig represents the default configuration for a rule
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFResult represents a single finding
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage holds a text message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes where a result was found
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation points to a file and region
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies a file
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion identifies a line/column range
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// SARIFReporter generates SARIF-formatted output from scan results
type SARIFReporter struct {
	report *scanners.ScanReport
}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter(report *scanners.ScanReport) *SARIFReporter {
	return &SARIFReporter{report: report}
}

// Generate produces the SARIF JSON output as bytes
func (sr *SARIFReporter) Generate() ([]byte, error) {
	sarifReport := SARIFReport{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs:    sr.buildRuns(),
	}

	return json.MarshalIndent(sarifReport, "", "  ")
}

// WriteFile writes the SARIF report to a file
func (sr *SARIFReporter) WriteFile(path string) error {
	data, err := sr.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate SARIF report: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write SARIF file: %w", err)
	}

	return nil
}

// buildRuns creates one SARIF run per tool
func (sr *SARIFReporter) buildRuns() []SARIFRun {
	// Group findings by tool
	findingsByTool := make(map[string][]scanners.Finding)
	for _, finding := range sr.report.AllFindings {
		findingsByTool[finding.Tool] = append(findingsByTool[finding.Tool], finding)
	}

	var runs []SARIFRun
	for tool, findings := range findingsByTool {
		runs = append(runs, sr.buildRun(tool, findings))
	}

	// If no findings, add a single empty run for DevSecOps Kit
	if len(runs) == 0 {
		runs = append(runs, SARIFRun{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name: "devsecops-kit",
				},
			},
			Results: []SARIFResult{},
		})
	}

	return runs
}

// buildRun creates a SARIF run for a single tool
func (sr *SARIFReporter) buildRun(tool string, findings []scanners.Finding) SARIFRun {
	// Collect unique rules
	rulesMap := make(map[string]SARIFRule)
	var results []SARIFResult

	for _, finding := range findings {
		ruleID := finding.RuleID
		if ruleID == "" {
			ruleID = fmt.Sprintf("%s-finding", tool)
		}

		// Add rule if not seen before
		if _, exists := rulesMap[ruleID]; !exists {
			rule := SARIFRule{
				ID: ruleID,
				DefaultConfig: &SARIFRuleConfig{
					Level: severityToSARIFLevel(finding.Severity),
				},
			}
			if finding.RemoteURL != "" {
				rule.HelpURI = finding.RemoteURL
			}
			rulesMap[ruleID] = rule
		}

		// Build result
		result := SARIFResult{
			RuleID:  ruleID,
			Level:   severityToSARIFLevel(finding.Severity),
			Message: SARIFMessage{Text: finding.Message},
		}

		// Add location if file is present
		if finding.File != "" {
			location := SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: finding.File,
					},
				},
			}

			if finding.Line > 0 {
				region := &SARIFRegion{StartLine: finding.Line}
				if finding.Column > 0 {
					region.StartColumn = finding.Column
				}
				location.PhysicalLocation.Region = region
			}

			result.Locations = []SARIFLocation{location}
		}

		results = append(results, result)
	}

	// Convert rules map to slice
	var rules []SARIFRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	return SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           toolDisplayName(tool),
				InformationURI: toolInfoURI(tool),
				Rules:          rules,
			},
		},
		Results: results,
	}
}

// severityToSARIFLevel maps severity strings to SARIF levels
func severityToSARIFLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "warning"
	}
}

// toolDisplayName returns a display name for a tool
func toolDisplayName(tool string) string {
	switch tool {
	case "semgrep":
		return "Semgrep"
	case "gitleaks":
		return "Gitleaks"
	case "trivy":
		return "Trivy"
	default:
		return tool
	}
}

// toolInfoURI returns the tool's homepage URL
func toolInfoURI(tool string) string {
	switch tool {
	case "semgrep":
		return "https://semgrep.dev"
	case "gitleaks":
		return "https://gitleaks.io"
	case "trivy":
		return "https://trivy.dev"
	default:
		return ""
	}
}

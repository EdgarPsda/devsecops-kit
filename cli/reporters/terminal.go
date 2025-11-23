package reporters

import (
	"fmt"
	"sort"
	"strings"

	"github.com/edgarpsda/devsecops-kit/cli/scanners"
)

// TerminalReporter generates human-friendly terminal output
type TerminalReporter struct {
	report *scanners.ScanReport
}

// NewTerminalReporter creates a new terminal reporter
func NewTerminalReporter(report *scanners.ScanReport) *TerminalReporter {
	return &TerminalReporter{report: report}
}

// Print outputs the security scan report to terminal with colors and formatting
func (tr *TerminalReporter) Print() {
	tr.printHeader()
	tr.printSummary()
	tr.printFindings()
	tr.printFooter()
}

// printHeader prints the report header
func (tr *TerminalReporter) printHeader() {
	fmt.Println()
	fmt.Println(colorCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println(colorCyan("📊 DevSecOps Kit Security Scan Report"))
	fmt.Println(colorCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
}

// printSummary prints the security summary
func (tr *TerminalReporter) printSummary() {
	fmt.Println()

	// Overall status
	statusIcon := "🔴"
	statusColor := colorRed
	if tr.report.Status == "PASS" {
		statusIcon = "🟢"
		statusColor = colorGreen
	} else if tr.report.Status == "WARN" {
		statusIcon = "🟡"
		statusColor = colorYellow
	}

	fmt.Println(statusColor(fmt.Sprintf("%s Status: %s", statusIcon, tr.report.Status)))

	if tr.report.BlockingCount > 0 {
		fmt.Println(colorRed(fmt.Sprintf("   ⚠️  %d issue(s) exceed thresholds", tr.report.BlockingCount)))
	}

	fmt.Println()
	fmt.Println(colorCyan("Summary by Tool:"))

	// Sort tools for consistent output
	tools := []string{"gitleaks", "semgrep", "trivy"}

	for _, tool := range tools {
		if result, ok := tr.report.Results[tool]; ok {
			tr.printToolSummary(tool, result)
		}
	}
}

// printToolSummary prints summary for a single tool
func (tr *TerminalReporter) printToolSummary(tool string, result *scanners.ScanResult) {
	if result.Status == "error" {
		fmt.Printf("  ❌ %s: %v\n", colorBold(tool), result.Error)
		return
	}

	if result.Status == "not_implemented" {
		fmt.Printf("  ⏭️  %s: Not yet implemented\n", colorBold(tool))
		return
	}

	total := result.Summary.Total
	if total == 0 {
		fmt.Printf("  ✅ %s: No findings\n", colorBold(tool))
		return
	}

	// Build severity breakdown
	severity := ""
	if result.Summary.Critical > 0 {
		severity += colorRed(fmt.Sprintf("🔴 CRITICAL:%d ", result.Summary.Critical))
	}
	if result.Summary.High > 0 {
		severity += colorYellow(fmt.Sprintf("🟠 HIGH:%d ", result.Summary.High))
	}
	if result.Summary.Medium > 0 {
		severity += colorYellow(fmt.Sprintf("🟡 MEDIUM:%d ", result.Summary.Medium))
	}
	if result.Summary.Low > 0 {
		severity += colorGray(fmt.Sprintf("🟢 LOW:%d ", result.Summary.Low))
	}

	fmt.Printf("  ⚠️  %s: %d finding(s) %s\n", colorBold(tool), total, severity)
}

// printFindings prints detailed findings
func (tr *TerminalReporter) printFindings() {
	if len(tr.report.AllFindings) == 0 {
		return
	}

	fmt.Println()
	fmt.Println(colorCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println(colorCyan("Detailed Findings:"))
	fmt.Println(colorCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	// Group findings by tool
	findingsByTool := make(map[string][]scanners.Finding)
	for _, finding := range tr.report.AllFindings {
		findingsByTool[finding.Tool] = append(findingsByTool[finding.Tool], finding)
	}

	// Sort tools
	tools := []string{"gitleaks", "semgrep", "trivy"}

	for _, tool := range tools {
		findings, ok := findingsByTool[tool]
		if !ok || len(findings) == 0 {
			continue
		}

		fmt.Println()
		fmt.Println(colorBold(fmt.Sprintf("🔍 %s (%d findings)", tool, len(findings))))

		// Sort findings by file and line
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].File != findings[j].File {
				return findings[i].File < findings[j].File
			}
			return findings[i].Line < findings[j].Line
		})

		// Print each finding
		for _, finding := range findings {
			tr.printFinding(finding)
		}
	}
}

// printFinding prints a single finding
func (tr *TerminalReporter) printFinding(finding scanners.Finding) {
	// Format: File:Line | Severity | Message
	severityColor := colorGray
	severityIcon := "❓"

	switch finding.Severity {
	case "CRITICAL":
		severityColor = colorRed
		severityIcon = "🔴"
	case "HIGH":
		severityColor = colorYellow
		severityIcon = "🟠"
	case "MEDIUM":
		severityColor = colorYellow
		severityIcon = "🟡"
	case "LOW":
		severityColor = colorGray
		severityIcon = "🟢"
	}

	fmt.Printf("  %s %s\n", severityIcon, severityColor(finding.File))
	if finding.Line > 0 {
		fmt.Printf("     Line %d | %s\n", finding.Line, severityColor(finding.Severity))
	} else {
		fmt.Printf("     %s\n", severityColor(finding.Severity))
	}

	// Truncate long messages
	msg := finding.Message
	if len(msg) > 80 {
		msg = msg[:77] + "..."
	}
	fmt.Printf("     %s\n", colorGray(msg))

	if finding.RuleID != "" {
		fmt.Printf("     Rule: %s\n", colorGray(finding.RuleID))
	}

	fmt.Println()
}

// printFooter prints the report footer
func (tr *TerminalReporter) printFooter() {
	fmt.Println(colorCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	if tr.report.BlockingCount > 0 {
		fmt.Println(colorRed("❌ Scan FAILED - Review findings above and remediate before proceeding"))
	} else {
		fmt.Println(colorGreen("✅ Scan PASSED - No blocking issues detected"))
	}

	fmt.Println(colorCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()
}

// Color functions for terminal output
func colorRed(s string) string {
	return fmt.Sprintf("\033[91m%s\033[0m", s)
}

func colorYellow(s string) string {
	return fmt.Sprintf("\033[93m%s\033[0m", s)
}

func colorGreen(s string) string {
	return fmt.Sprintf("\033[92m%s\033[0m", s)
}

func colorCyan(s string) string {
	return fmt.Sprintf("\033[96m%s\033[0m", s)
}

func colorGray(s string) string {
	return fmt.Sprintf("\033[90m%s\033[0m", s)
}

func colorBold(s string) string {
	return fmt.Sprintf("\033[1m%s\033[0m", s)
}

// StringDivider returns a divider string of given character
func StringDivider(char string, length int) string {
	return strings.Repeat(char, length)
}

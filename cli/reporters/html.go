package reporters

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/edgarpsda/devsecops-kit/cli/scanners"
)

// HTMLReporter generates HTML security reports
type HTMLReporter struct {
	report *scanners.ScanReport
}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter(report *scanners.ScanReport) *HTMLReporter {
	return &HTMLReporter{report: report}
}

// WriteFile generates an HTML report and writes it to a file
func (hr *HTMLReporter) WriteFile(filePath string) error {
	html := hr.generateHTML()
	if err := os.WriteFile(filePath, []byte(html), 0o644); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}
	return nil
}

// generateHTML creates the complete HTML report
func (hr *HTMLReporter) generateHTML() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>DevSecOps Kit Security Report</title>
	<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
			background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
			min-height: 100vh;
			padding: 20px;
		}

		.container {
			max-width: 1200px;
			margin: 0 auto;
		}

		header {
			background: white;
			border-radius: 8px;
			padding: 30px;
			margin-bottom: 20px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
		}

		h1 {
			color: #333;
			margin-bottom: 10px;
			display: flex;
			align-items: center;
			gap: 10px;
		}

		.timestamp {
			color: #666;
			font-size: 14px;
		}

		.status-badge {
			display: inline-block;
			padding: 8px 16px;
			border-radius: 20px;
			font-weight: 600;
			margin-top: 15px;
		}

		.status-pass {
			background: #d4edda;
			color: #155724;
		}

		.status-fail {
			background: #f8d7da;
			color: #721c24;
		}

		.summary {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
			gap: 20px;
			margin-bottom: 30px;
		}

		.card {
			background: white;
			border-radius: 8px;
			padding: 20px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
		}

		.card h3 {
			color: #333;
			margin-bottom: 15px;
			font-size: 14px;
			text-transform: uppercase;
			letter-spacing: 0.5px;
		}

		.stat {
			display: flex;
			justify-content: space-between;
			padding: 8px 0;
			border-bottom: 1px solid #eee;
		}

		.stat:last-child {
			border-bottom: none;
		}

		.stat-label {
			color: #666;
		}

		.stat-value {
			font-weight: 600;
			color: #333;
		}

		.severity-critical { color: #dc3545; }
		.severity-high { color: #fd7e14; }
		.severity-medium { color: #ffc107; }
		.severity-low { color: #28a745; }

		.charts {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
			gap: 20px;
			margin-bottom: 30px;
		}

		.chart-container {
			background: white;
			border-radius: 8px;
			padding: 20px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
		}

		.chart-container h3 {
			margin-bottom: 20px;
			color: #333;
		}

		canvas {
			max-height: 300px;
		}

		.findings {
			background: white;
			border-radius: 8px;
			padding: 20px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
		}

		.findings h2 {
			color: #333;
			margin-bottom: 20px;
		}

		.tool-section {
			margin-bottom: 30px;
		}

		.tool-title {
			color: #667eea;
			font-size: 18px;
			font-weight: 600;
			margin-bottom: 15px;
			padding-bottom: 10px;
			border-bottom: 2px solid #667eea;
		}

		.finding {
			border-left: 4px solid #ddd;
			padding: 15px;
			margin-bottom: 10px;
			background: #f9f9f9;
			border-radius: 4px;
		}

		.finding.critical {
			border-left-color: #dc3545;
			background: #fff5f5;
		}

		.finding.high {
			border-left-color: #fd7e14;
			background: #fffaf5;
		}

		.finding.medium {
			border-left-color: #ffc107;
			background: #fffef5;
		}

		.finding.low {
			border-left-color: #28a745;
			background: #f5fff9;
		}

		.finding-header {
			display: flex;
			justify-content: space-between;
			align-items: start;
			margin-bottom: 10px;
		}

		.finding-file {
			font-weight: 600;
			color: #333;
		}

		.finding-severity {
			font-weight: 600;
			font-size: 12px;
			text-transform: uppercase;
			padding: 4px 8px;
			border-radius: 3px;
		}

		.severity-critical { background: #dc3545; color: white; }
		.severity-high { background: #fd7e14; color: white; }
		.severity-medium { background: #ffc107; color: #333; }
		.severity-low { background: #28a745; color: white; }

		.finding-line {
			color: #666;
			font-size: 12px;
			margin-bottom: 8px;
		}

		.finding-message {
			color: #555;
			margin-bottom: 8px;
		}

		.finding-rule {
			color: #999;
			font-size: 12px;
			font-family: 'Courier New', monospace;
		}

		.no-findings {
			text-align: center;
			padding: 40px;
			color: #666;
		}

		.export-btn {
			background: #667eea;
			color: white;
			border: none;
			padding: 10px 20px;
			border-radius: 4px;
			cursor: pointer;
			font-size: 14px;
			margin-bottom: 20px;
		}

		.export-btn:hover {
			background: #5568d3;
		}

		footer {
			text-align: center;
			color: white;
			margin-top: 40px;
			padding: 20px;
		}

		@media (max-width: 768px) {
			.summary {
				grid-template-columns: 1fr;
			}

			.charts {
				grid-template-columns: 1fr;
			}

			header {
				padding: 20px;
			}

			h1 {
				font-size: 20px;
			}
		}

		@media print {
			body {
				background: white;
			}

			.export-btn {
				display: none;
			}
		}
	</style>
</head>
<body>
	<div class="container">
		<header>
			<h1>🔐 DevSecOps Kit Security Report</h1>
			<p class="timestamp">Generated: %s</p>
			<div class="status-badge status-%s">
				%s Status: %s
			</div>
			%s
		</header>

		<div class="summary">
			%s
		</div>

		<div class="charts">
			%s
		</div>

		<div class="findings">
			<button class="export-btn" onclick="downloadJSON()">📥 Export as JSON</button>
			<h2>Detailed Findings</h2>
			%s
		</div>

		<footer>
			<p>DevSecOps Kit v0.4.1 • <a href="https://github.com/edgarpsda/devsecops-kit" style="color: white;">GitHub</a></p>
		</footer>
	</div>

	<script>
		const reportData = %s;

		function downloadJSON() {
			const dataStr = JSON.stringify(reportData, null, 2);
			const dataBlob = new Blob([dataStr], {type: 'application/json'});
			const url = URL.createObjectURL(dataBlob);
			const link = document.createElement('a');
			link.href = url;
			link.download = 'security-report.json';
			link.click();
		}
	</script>
</body>
</html>`,
		hr.report.Timestamp,
		hr.getStatusClass(),
		hr.getStatusIcon(),
		hr.report.Status,
		hr.getBlockingCountHTML(),
		hr.generateSummaryCards(),
		hr.generateCharts(),
		hr.generateFindings(),
		hr.getReportDataJSON(),
	)
}

// getStatusIcon returns the emoji for the status
func (hr *HTMLReporter) getStatusIcon() string {
	if hr.report.Status == "PASS" {
		return "✅"
	}
	return "❌"
}

// getStatusClass returns the CSS class for the status
func (hr *HTMLReporter) getStatusClass() string {
	if hr.report.Status == "PASS" {
		return "pass"
	}
	return "fail"
}

// getBlockingCountHTML returns HTML for blocking count if applicable
func (hr *HTMLReporter) getBlockingCountHTML() string {
	if hr.report.BlockingCount > 0 {
		return fmt.Sprintf(`<p style="color: #721c24; margin-top: 10px;"><strong>⚠️ %d issue(s) exceed configured thresholds</strong></p>`, hr.report.BlockingCount)
	}
	return ""
}

// generateSummaryCards creates the summary statistics cards
func (hr *HTMLReporter) generateSummaryCards() string {
	html := ""

	// Overall summary
	html += `<div class="card">
		<h3>Overall Summary</h3>
		<div class="stat">
			<span class="stat-label">Total Findings</span>
			<span class="stat-value">` + fmt.Sprintf("%d", len(hr.report.AllFindings)) + `</span>
		</div>
		<div class="stat">
			<span class="stat-label">Status</span>
			<span class="stat-value">` + hr.report.Status + `</span>
		</div>
		<div class="stat">
			<span class="stat-label">Blocking Issues</span>
			<span class="stat-value">` + fmt.Sprintf("%d", hr.report.BlockingCount) + `</span>
		</div>
	</div>`

	// Per-tool summaries
	tools := []string{"semgrep", "gitleaks", "trivy"}
	for _, tool := range tools {
		if result, ok := hr.report.Results[tool]; ok && result.Status == "success" {
			html += fmt.Sprintf(`<div class="card">
				<h3>%s</h3>
				<div class="stat">
					<span class="stat-label">Total</span>
					<span class="stat-value">%d</span>
				</div>
				<div class="stat">
					<span class="stat-label"><span class="severity-critical">CRITICAL</span></span>
					<span class="stat-value">%d</span>
				</div>
				<div class="stat">
					<span class="stat-label"><span class="severity-high">HIGH</span></span>
					<span class="stat-value">%d</span>
				</div>
				<div class="stat">
					<span class="stat-label"><span class="severity-medium">MEDIUM</span></span>
					<span class="stat-value">%d</span>
				</div>
				<div class="stat">
					<span class="stat-label"><span class="severity-low">LOW</span></span>
					<span class="stat-value">%d</span>
				</div>
			</div>`,
				tool,
				result.Summary.Total,
				result.Summary.Critical,
				result.Summary.High,
				result.Summary.Medium,
				result.Summary.Low,
			)
		}
	}

	return html
}

// generateCharts creates the chart sections
func (hr *HTMLReporter) generateCharts() string {
	html := ""

	// Severity breakdown chart
	if len(hr.report.AllFindings) > 0 {
		html += `<div class="chart-container">
			<h3>Severity Distribution</h3>
			<canvas id="severityChart"></canvas>
		</div>

		<div class="chart-container">
			<h3>Findings by Tool</h3>
			<canvas id="toolChart"></canvas>
		</div>`

		html += `<script>
			// Severity chart
			const severityCtx = document.getElementById('severityChart').getContext('2d');
			const severityData = {
				CRITICAL: 0,
				HIGH: 0,
				MEDIUM: 0,
				LOW: 0
			};
			reportData.all_findings.forEach(f => {
				severityData[f.severity] = (severityData[f.severity] || 0) + 1;
			});

			new Chart(severityCtx, {
				type: 'doughnut',
				data: {
					labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
					datasets: [{
						data: [severityData.CRITICAL, severityData.HIGH, severityData.MEDIUM, severityData.LOW],
						backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
						borderColor: '#fff',
						borderWidth: 2
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: true,
					plugins: {
						legend: {
							position: 'bottom'
						}
					}
				}
			});

			// Tool chart
			const toolCtx = document.getElementById('toolChart').getContext('2d');
			const toolData = {};
			reportData.all_findings.forEach(f => {
				toolData[f.tool] = (toolData[f.tool] || 0) + 1;
			});

			new Chart(toolCtx, {
				type: 'bar',
				data: {
					labels: Object.keys(toolData),
					datasets: [{
						label: 'Findings',
						data: Object.values(toolData),
						backgroundColor: '#667eea',
						borderRadius: 4
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: true,
					plugins: {
						legend: {
							display: false
						}
					},
					scales: {
						y: {
							beginAtZero: true
						}
					}
				}
			});
		</script>`
	}

	return html
}

// generateFindings creates the detailed findings section
func (hr *HTMLReporter) generateFindings() string {
	if len(hr.report.AllFindings) == 0 {
		return `<div class="no-findings">✅ No security findings detected!</div>`
	}

	// Group findings by tool
	findingsByTool := make(map[string][]scanners.Finding)
	for _, finding := range hr.report.AllFindings {
		findingsByTool[finding.Tool] = append(findingsByTool[finding.Tool], finding)
	}

	html := ""
	tools := []string{"semgrep", "gitleaks", "trivy"}

	for _, tool := range tools {
		findings, ok := findingsByTool[tool]
		if !ok || len(findings) == 0 {
			continue
		}

		html += fmt.Sprintf(`<div class="tool-section">
			<div class="tool-title">🔍 %s (%d findings)</div>`, tool, len(findings))

		for _, finding := range findings {
			severityClass := "low"
			switch finding.Severity {
			case "CRITICAL":
				severityClass = "critical"
			case "HIGH":
				severityClass = "high"
			case "MEDIUM":
				severityClass = "medium"
			}

			lineHTML := ""
			if finding.Line > 0 {
				lineHTML = fmt.Sprintf(`<div class="finding-line">📍 Line %d</div>`, finding.Line)
			}

			html += fmt.Sprintf(`<div class="finding %s">
				<div class="finding-header">
					<div class="finding-file">%s</div>
					<div class="finding-severity severity-%s">%s</div>
				</div>
				%s
				<div class="finding-message">%s</div>
				<div class="finding-rule">Rule: %s</div>
			</div>`, severityClass, finding.File, severityClass, finding.Severity, lineHTML, finding.Message, finding.RuleID)
		}

		html += `</div>`
	}

	return html
}

// getReportDataJSON returns the report as JSON for download
func (hr *HTMLReporter) getReportDataJSON() string {
	data, _ := json.Marshal(hr.report)
	return string(data)
}

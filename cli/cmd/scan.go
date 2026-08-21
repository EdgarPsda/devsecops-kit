package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/edgarpsda/devsecops-kit/cli/ai"
	"github.com/edgarpsda/devsecops-kit/cli/config"
	"github.com/edgarpsda/devsecops-kit/cli/detectors"
	"github.com/edgarpsda/devsecops-kit/cli/reporters"
	"github.com/edgarpsda/devsecops-kit/cli/scanners"
	"github.com/spf13/cobra"
)

var (
	scanTool            string
	scanFailOnThreshold bool
	scanOutputFormat    string
	scanConfigPath      string
	scanOpenReport      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scans locally",
	Long:  "Execute Semgrep, Gitleaks, and Trivy scans on your project directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVar(&scanTool, "tool", "", "Specific tool to run (semgrep, gitleaks, trivy)")
	scanCmd.Flags().BoolVar(&scanFailOnThreshold, "fail-on-threshold", false, "Exit with code 1 if findings exceed thresholds")
	scanCmd.Flags().StringVar(&scanOutputFormat, "format", "terminal", "Output format: terminal, json, html, sarif")
	scanCmd.Flags().StringVar(&scanConfigPath, "config", "security-config.yml", "Path to security-config.yml")
	scanCmd.Flags().BoolVar(&scanOpenReport, "open", false, "Auto-open HTML report in browser (requires --format=html)")
}

func runScan() error {
	// Get current working directory
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Detect project to get Docker info
	projectInfo, err := detectors.DetectProject(dir)
	if err != nil {
		// Not fatal - project detection can fail
		projectInfo = &detectors.ProjectInfo{RootDir: dir}
	}

	// Load configuration
	secConfig, err := config.LoadConfig(filepath.Join(dir, scanConfigPath))
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Fprintln(os.Stderr, "🔍 Starting security scans...")

	// Build scan options from config
	options := scanners.ScanOptions{
		EnableSemgrep:    secConfig.Tools.Semgrep,
		EnableGitleaks:   secConfig.Tools.Gitleaks,
		EnableTrivy:      secConfig.Tools.Trivy,
		EnableTrivyImage: secConfig.Tools.Trivy && projectInfo.HasDocker,
		EnableLicenses:   secConfig.Licenses.Enabled,
		EnableCheckov:    secConfig.Tools.Checkov,
		DockerImages:     projectInfo.DockerImages,
		ExcludePaths:     secConfig.ExcludePaths,
		FailOnThresholds: secConfig.FailOn,
		LicenseConfig: scanners.LicenseConfig{
			Enabled: secConfig.Licenses.Enabled,
			Deny:    secConfig.Licenses.Deny,
			Allow:   secConfig.Licenses.Allow,
		},
		Verbose: false,
	}

	// If specific tool requested, disable others
	if scanTool != "" {
		options.EnableSemgrep = scanTool == "semgrep"
		options.EnableGitleaks = scanTool == "gitleaks"
		options.EnableTrivy = scanTool == "trivy"
		options.EnableLicenses = scanTool == "licenses"
		options.EnableCheckov = scanTool == "checkov"
	}

	// Run orchestrator
	orchestrator := scanners.NewOrchestrator(dir, options)
	report, err := orchestrator.Run()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Enrich findings with AI suggestions if enabled
	if secConfig.AI.Enabled {
		if err := config.ValidateAIConfig(secConfig.AI); err != nil {
			return err
		}
		apiKey := secConfig.AI.APIKey
		if apiKey == "" {
			switch secConfig.AI.Provider {
			case "openai":
				apiKey = os.Getenv("OPENAI_API_KEY")
			case "anthropic":
				apiKey = os.Getenv("ANTHROPIC_API_KEY")
			}
		}
		aiClient := ai.NewClient(ai.Config{
			Enabled:  true,
			Provider: secConfig.AI.Provider,
			Model:    secConfig.AI.Model,
			Endpoint: secConfig.AI.Endpoint,
			APIKey:   apiKey,
		})
		fmt.Fprintln(os.Stderr, "🤖 Generating AI fix suggestions for HIGH/CRITICAL findings...")
		aiClient.EnrichFindings(report.AllFindings)
		// Sync enriched AllFindings back into per-tool Results
		for i := range report.AllFindings {
			f := &report.AllFindings[i]
			if f.AISuggestion == "" {
				continue
			}
			if result, ok := report.Results[f.Tool]; ok {
				for j := range result.Findings {
					if result.Findings[j].RuleID == f.RuleID && result.Findings[j].File == f.File {
						result.Findings[j].AISuggestion = f.AISuggestion
						break
					}
				}
			}
		}
	}

	// Output results
	switch scanOutputFormat {
	case "json":
		return outputJSON(report)
	case "html":
		return outputHTML(report, scanOpenReport)
	case "sarif":
		return outputSARIF(report)
	case "terminal":
		fallthrough
	default:
		reporter := reporters.NewTerminalReporter(report)
		reporter.Print()
	}

	// Exit with appropriate code
	if scanFailOnThreshold && report.BlockingCount > 0 {
		return fmt.Errorf("scan failed: %d issue(s) exceed configured thresholds", report.BlockingCount)
	}

	return nil
}

// outputJSON outputs the report as JSON
func outputJSON(report *scanners.ScanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// outputSARIF generates a SARIF report
func outputSARIF(report *scanners.ScanReport) error {
	sarifReporter := reporters.NewSARIFReporter(report)

	reportPath := "security-report.sarif"
	if err := sarifReporter.WriteFile(reportPath); err != nil {
		return err
	}

	fmt.Printf("✅ SARIF report generated: %s\n", reportPath)
	return nil
}

// outputHTML generates and optionally opens an HTML report
func outputHTML(report *scanners.ScanReport, openBrowser bool) error {
	htmlReporter := reporters.NewHTMLReporter(report)

	reportPath := "security-report.html"
	if err := htmlReporter.WriteFile(reportPath); err != nil {
		return err
	}

	fmt.Printf("✅ HTML report generated: %s\n", reportPath)

	if openBrowser {
		// Try to open in browser
		absPath, err := filepath.Abs(reportPath)
		if err == nil {
			fileURL := fmt.Sprintf("file://%s", absPath)
			openInBrowser(fileURL)
			fmt.Printf("🌐 Opening report in browser...\n")
		}
	}

	return nil
}

// openInBrowser opens a URL in the default browser
func openInBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	}

	if cmd != nil {
		_ = cmd.Start() // Ignore errors, browser might not be available
	}
}

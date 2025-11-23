package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/edgarpsda/devsecops-kit/cli/config"
	"github.com/edgarpsda/devsecops-kit/cli/detectors"
	"github.com/edgarpsda/devsecops-kit/cli/reporters"
	"github.com/edgarpsda/devsecops-kit/cli/scanners"
)

var (
	scanTool             string
	scanFailOnThreshold  bool
	scanOutputFormat     string
	scanConfigPath       string
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
	scanCmd.Flags().StringVar(&scanOutputFormat, "format", "terminal", "Output format: terminal, json")
	scanCmd.Flags().StringVar(&scanConfigPath, "config", "security-config.yml", "Path to security-config.yml")
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

	fmt.Println("🔍 Starting security scans...")
	fmt.Println()

	// Build scan options from config
	options := scanners.ScanOptions{
		EnableSemgrep:     secConfig.Tools.Semgrep,
		EnableGitleaks:    secConfig.Tools.Gitleaks,
		EnableTrivy:       secConfig.Tools.Trivy,
		EnableTrivyImage:  secConfig.Tools.Trivy && projectInfo.HasDocker,
		DockerImages:      projectInfo.DockerImages,
		ExcludePaths:      secConfig.ExcludePaths,
		FailOnThresholds:  secConfig.FailOn,
		Verbose:           false,
	}

	// If specific tool requested, disable others
	if scanTool != "" {
		options.EnableSemgrep = scanTool == "semgrep"
		options.EnableGitleaks = scanTool == "gitleaks"
		options.EnableTrivy = scanTool == "trivy"
	}

	// Run orchestrator
	orchestrator := scanners.NewOrchestrator(dir, options)
	report, err := orchestrator.Run()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	switch scanOutputFormat {
	case "json":
		return outputJSON(report)
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

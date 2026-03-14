package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var (
	sbomFormat string
	sbomOutput string
	sbomOpen   bool
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Generate a Software Bill of Materials (SBOM)",
	Long: `Generate an SBOM for your project using Trivy.

Supports CycloneDX (default) and SPDX formats. The SBOM lists all
dependencies, licenses, and component metadata for compliance and
supply chain security.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSBOM()
	},
}

func init() {
	rootCmd.AddCommand(sbomCmd)

	sbomCmd.Flags().StringVar(&sbomFormat, "format", "cyclonedx", "SBOM format: cyclonedx, spdx")
	sbomCmd.Flags().StringVar(&sbomOutput, "output", "", "Output file path (default: sbom-<format>.json)")
	sbomCmd.Flags().BoolVar(&sbomOpen, "open", false, "Auto-open the SBOM file after generation")
}

func runSBOM() error {
	// Check if Trivy is installed
	if _, err := exec.LookPath("trivy"); err != nil {
		return fmt.Errorf("trivy is not installed. Install with: brew install trivy or visit https://github.com/aquasecurity/trivy")
	}

	// Get working directory
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Resolve SBOM format
	trivyFormat, err := resolveTrivyFormat(sbomFormat)
	if err != nil {
		return err
	}

	// Resolve output file path
	outputPath := sbomOutput
	if outputPath == "" {
		outputPath = fmt.Sprintf("sbom-%s.json", sbomFormat)
	}

	fmt.Printf("📦 Generating SBOM (%s format)...\n", sbomFormat)

	// Build Trivy SBOM command
	cmd := exec.Command("trivy", "fs", ".", "--format", trivyFormat, "--output", outputPath)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("SBOM generation failed: %w", err)
	}

	// Verify file was created
	absPath, err := filepath.Abs(outputPath)
	if err != nil {
		absPath = outputPath
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("SBOM file was not created: %w", err)
	}

	fmt.Printf("✅ SBOM generated: %s (%s)\n", outputPath, formatFileSize(info.Size()))
	fmt.Printf("   Format: %s\n", strings.ToUpper(sbomFormat))

	if sbomOpen {
		openSBOMFile(absPath)
		fmt.Println("🌐 Opening SBOM file...")
	}

	return nil
}

// resolveTrivyFormat maps user-facing format names to Trivy format flags
func resolveTrivyFormat(format string) (string, error) {
	switch strings.ToLower(format) {
	case "cyclonedx":
		return "cyclonedx", nil
	case "spdx":
		return "spdx-json", nil
	default:
		return "", fmt.Errorf("unsupported SBOM format: %s (supported: cyclonedx, spdx)", format)
	}
}

// formatFileSize returns a human-readable file size
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// openSBOMFile opens the SBOM file in the default application
func openSBOMFile(path string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", path)
	}

	if cmd != nil {
		_ = cmd.Start()
	}
}

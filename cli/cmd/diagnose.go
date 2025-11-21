package cmd

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/edgarpsda/devsecops-kit/cli/detectors"
)

var diagnosePath string

// diagnoseCmd defines the `devsecops diagnose` command.
var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Check DevSecOps environment and project readiness",
	Long: `Run a series of checks to verify that your environment and project
are ready to use DevSecOps Kit.

It checks:
- Project type detection (Node.js / Go)
- Availability of Semgrep, Gitleaks, Trivy
- Docker CLI presence (for container-based scanners in the future)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiagnose()
	},
}

func init() {
	// Register the diagnose command with the root command.
	rootCmd.AddCommand(diagnoseCmd)

	diagnoseCmd.Flags().StringVar(
		&diagnosePath,
		"path",
		".",
		"Project root path (default: current directory)",
	)
}

func runDiagnose() error {
	root := diagnosePath
	if root == "" {
		root = "."
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("failed to resolve path %q: %w", root, err)
	}

	fmt.Println("🩺 DevSecOps Kit Diagnose")
	fmt.Println("-------------------------")
	fmt.Printf("Project root: %s\n\n", absRoot)

	// 1) Project detection
	fmt.Println("🔍 Project detection")
	det, err := detectors.DetectProject(absRoot)
	if err != nil {
		fmt.Printf("  ❌ Failed to detect project: %v\n\n", err)
	} else {
		fmt.Println("  ✅ Detection succeeded:")
		fmt.Printf("     • Language:  %s\n", det.Language)
		fmt.Printf("     • Framework: %s\n", det.Framework)
		fmt.Printf("     • Package:   %s\n", det.PackageFile)
		fmt.Printf("     • RootDir:   %s\n\n", det.RootDir)
	}

	// 2) Tool checks
	fmt.Println("🛠 Tool checks")
	checkAndPrintTool("Semgrep", "semgrep")
	checkAndPrintTool("Gitleaks", "gitleaks")
	checkAndPrintTool("Trivy", "trivy")
	checkAndPrintTool("Docker", "docker")

	fmt.Println()
	fmt.Println("✅ Diagnose finished.")
	fmt.Println("If some tools are missing (⚠️ / ❌), install them or adjust your pipeline configuration.")

	// Missing tools are informational, not a hard error.
	return nil
}

func checkAndPrintTool(label, binary string) {
	found, path, err := checkBinary(binary)
	if err != nil {
		fmt.Printf("  ❌ %s: error while checking: %v\n", label, err)
		return
	}

	if !found {
		fmt.Printf("  ⚠️  %s: NOT found on PATH\n", label)
		return
	}

	fmt.Printf("  ✅ %s: found at %s\n", label, path)
}

func checkBinary(name string) (bool, string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		// Not found is not a "real" error; just report false.
		if ee, ok := err.(*exec.Error); ok && ee.Err == exec.ErrNotFound {
			return false, "", nil
		}
		return false, "", err
	}
	return true, path, nil
}

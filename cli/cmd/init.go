package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/edgarpsda/devsecops-kit/cli/detectors"
	"github.com/edgarpsda/devsecops-kit/cli/generators"
	"github.com/spf13/cobra"
)

var (
	severityFlag   string
	noSemgrepFlag  bool
	noTrivyFlag    bool
	noGitleaksFlag bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize DevSecOps workflow configuration",
	Long: `Initialize DevSecOps Kit in your project.

This command detects your project type and generates:
- .github/workflows/security.yml
- security-config.yml

You can customize severity threshold and enabled tools with flags.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("🔍 Detecting project type...")

		dir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot determine working directory: %w", err)
		}

		project, err := detectors.DetectProject(dir)
		if err != nil {
			return fmt.Errorf("project detection failed: %w", err)
		}

		fmt.Printf("✅ Detected: %s (%s)\n", project.Language, project.Framework)

		// Normalize severity
		severity := strings.ToLower(severityFlag)
		switch severity {
		case "low", "medium", "high", "critical":
			// ok
		default:
			fmt.Printf("⚠️  Unknown severity '%s', defaulting to 'high'\n", severityFlag)
			severity = "high"
		}

		cfg := &generators.InitConfig{
			Project:           project,
			SeverityThreshold: severity,
			Tools: generators.ToolsConfig{
				Semgrep:  !noSemgrepFlag,
				Trivy:    !noTrivyFlag,
				Gitleaks: !noGitleaksFlag,
			},
		}

		// Ensure .github/workflows exists
		wfDir := filepath.Join(dir, ".github", "workflows")
		if err := os.MkdirAll(wfDir, 0o755); err != nil {
			return fmt.Errorf("failed to create workflows directory: %w", err)
		}

		fmt.Println("⚙️  Generating workflow + config files...")

		if err := generators.GenerateGithubActions(cfg); err != nil {
			return err
		}
		if err := generators.GenerateSecurityConfig(cfg); err != nil {
			return err
		}

		fmt.Println("\n🎉 Done! DevSecOps Kit initialized.")
		fmt.Println("Files created:")
		fmt.Println(" - .github/workflows/security.yml")
		fmt.Println(" - security-config.yml")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&severityFlag, "severity", "high", "Severity threshold (low, medium, high, critical)")
	initCmd.Flags().BoolVar(&noSemgrepFlag, "no-semgrep", false, "Disable Semgrep in generated workflow")
	initCmd.Flags().BoolVar(&noTrivyFlag, "no-trivy", false, "Disable Trivy in generated workflow")
	initCmd.Flags().BoolVar(&noGitleaksFlag, "no-gitleaks", false, "Disable Gitleaks in generated workflow")
}

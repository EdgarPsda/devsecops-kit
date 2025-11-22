package cmd

import (
	"bufio"
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
	wizardFlag     bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize DevSecOps workflow configuration",
	Long: `Initialize DevSecOps Kit in your project.

This command detects your project type and generates:
- .github/workflows/security.yml
- security-config.yml

You can customize severity threshold and enabled tools with flags,
or run interactively with --wizard.
`,
	RunE: func(cmd *cobra.Command, args []string) error {

		if wizardFlag {
			return runInitWizard()
		}

		// Non-interactive mode (original behavior)
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
	initCmd.Flags().BoolVar(&wizardFlag, "wizard", false, "Run interactive guided setup")
}

//
// -----------------------------
// INTERACTIVE WIZARD MODE
// -----------------------------
//

func runInitWizard() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("🧙 Welcome to DevSecOps Kit Wizard!")
	fmt.Println("-----------------------------------")

	// Detect project type automatically
	dir, _ := os.Getwd()
	project, err := detectors.DetectProject(dir)
	if err != nil {
		return fmt.Errorf("project detection failed: %w", err)
	}

	fmt.Printf("🔍 Detected project: %s (%s)\n", project.Language, project.Framework)
	if !askYesNo(reader, "Is this correct? (Y/n): ", true) {
		fmt.Println("❌ Aborted by user.")
		return nil
	}

	// Choose tools
	fmt.Println("\n🛠 Select tools to enable:")

	enableSemgrep := askYesNo(reader, "Enable Semgrep? (Y/n): ", true)
	enableGitleaks := askYesNo(reader, "Enable Gitleaks? (Y/n): ", true)
	enableTrivy := askYesNo(reader, "Enable Trivy? (Y/n): ", true)

	// Select severity
	fmt.Println("\n🎚 Choose severity threshold:")
	severity := askChoice(reader, "low | medium | high | critical [default: high]: ",
		[]string{"low", "medium", "high", "critical"},
		"high",
	)

	// Show summary
	fmt.Println("\n📋 Summary")
	fmt.Println("----------------------------------")
	fmt.Printf("Language:     %s\n", project.Language)
	fmt.Printf("Framework:    %s\n", project.Framework)
	fmt.Printf("Severity:     %s\n", severity)
	fmt.Printf("Tools:\n")
	fmt.Printf("  - Semgrep:  %v\n", enableSemgrep)
	fmt.Printf("  - Gitleaks: %v\n", enableGitleaks)
	fmt.Printf("  - Trivy:    %v\n", enableTrivy)

	if !askYesNo(reader, "\nProceed and generate files? (Y/n): ", true) {
		fmt.Println("❌ Aborted by user.")
		return nil
	}

	// Generate config
	cfg := &generators.InitConfig{
		Project:           project,
		SeverityThreshold: severity,
		Tools: generators.ToolsConfig{
			Semgrep:  enableSemgrep,
			Gitleaks: enableGitleaks,
			Trivy:    enableTrivy,
		},
	}

	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		return fmt.Errorf("failed to create workflows directory: %w", err)
	}

	fmt.Println("\n⚙️  Generating workflow + config files...")

	if err := generators.GenerateGithubActions(cfg); err != nil {
		return err
	}
	if err := generators.GenerateSecurityConfig(cfg); err != nil {
		return err
	}

	fmt.Println("\n🎉 Setup complete!")
	fmt.Println("Generated:")
	fmt.Println(" - .github/workflows/security.yml")
	fmt.Println(" - security-config.yml")

	return nil
}

//
// -----------------------------
// HELPER FUNCTIONS
// -----------------------------
//

func askYesNo(reader *bufio.Reader, prompt string, def bool) bool {
	fmt.Print(prompt)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))

	if resp == "" {
		return def
	}
	return resp == "y" || resp == "yes"
}

func askChoice(reader *bufio.Reader, prompt string, valid []string, def string) string {
	for {
		fmt.Print(prompt)
		resp, _ := reader.ReadString('\n')
		resp = strings.TrimSpace(strings.ToLower(resp))

		if resp == "" {
			return def
		}

		for _, v := range valid {
			if resp == v {
				return resp
			}
		}

		fmt.Println("❌ Invalid choice, try again.")
	}
}

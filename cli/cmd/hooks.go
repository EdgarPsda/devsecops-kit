package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	hooksPreCommit bool
	hooksPrePush   bool
	hooksUninstall bool
)

var hooksCmd = &cobra.Command{
	Use:   "init-hooks",
	Short: "Initialize git pre-commit/pre-push hooks for security scanning",
	Long: `Initialize git hooks to automatically run security scans before commits and pushes.

Examples:
  devsecops init-hooks              # Install both pre-commit and pre-push hooks
  devsecops init-hooks --uninstall  # Remove all installed hooks
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInitHooks()
	},
}

func init() {
	rootCmd.AddCommand(hooksCmd)

	hooksCmd.Flags().BoolVar(&hooksUninstall, "uninstall", false, "Remove installed git hooks")
	hooksCmd.Flags().BoolVar(&hooksPreCommit, "pre-commit", true, "Install pre-commit hook (blocks commits with security issues)")
	hooksCmd.Flags().BoolVar(&hooksPrePush, "pre-push", true, "Install pre-push hook (warns about security issues)")
}

func runInitHooks() error {
	// Get git directory
	gitDir, err := getGitDir()
	if err != nil {
		return fmt.Errorf("not a git repository: %w", err)
	}

	hooksDir := filepath.Join(gitDir, "hooks")

	if hooksUninstall {
		return uninstallHooks(hooksDir)
	}

	return installHooks(hooksDir)
}

// getGitDir finds the .git directory by walking up the directory tree
func getGitDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
			return gitPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			return "", fmt.Errorf("no .git directory found")
		}
		dir = parent
	}
}

// installHooks creates pre-commit and pre-push hooks
func installHooks(hooksDir string) error {
	// Ensure hooks directory exists
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	installed := false

	// Install pre-commit hook
	if hooksPreCommit {
		preCommitPath := filepath.Join(hooksDir, "pre-commit")
		if err := createPreCommitHook(preCommitPath); err != nil {
			return err
		}
		fmt.Printf("✅ Installed: %s\n", preCommitPath)
		installed = true
	}

	// Install pre-push hook
	if hooksPrePush {
		prePushPath := filepath.Join(hooksDir, "pre-push")
		if err := createPrePushHook(prePushPath); err != nil {
			return err
		}
		fmt.Printf("✅ Installed: %s\n", prePushPath)
		installed = true
	}

	if !installed {
		return fmt.Errorf("no hooks to install")
	}

	fmt.Println()
	fmt.Println("🎉 Git hooks installed successfully!")
	fmt.Println()
	fmt.Println("Behavior:")
	fmt.Println("  • pre-commit:  Blocks commits if security issues exceed thresholds")
	fmt.Println("  • pre-push:    Warns about security issues but allows push")
	fmt.Println()
	fmt.Println("To remove hooks, run: devsecops init-hooks --uninstall")

	return nil
}

// uninstallHooks removes pre-commit and pre-push hooks
func uninstallHooks(hooksDir string) error {
	preCommitPath := filepath.Join(hooksDir, "pre-commit")
	prePushPath := filepath.Join(hooksDir, "pre-push")

	preCommitRemoved := false
	prePushRemoved := false

	// Remove pre-commit hook
	if _, err := os.Stat(preCommitPath); err == nil {
		if err := os.Remove(preCommitPath); err != nil {
			return fmt.Errorf("failed to remove pre-commit hook: %w", err)
		}
		fmt.Printf("✅ Removed: %s\n", preCommitPath)
		preCommitRemoved = true
	}

	// Remove pre-push hook
	if _, err := os.Stat(prePushPath); err == nil {
		if err := os.Remove(prePushPath); err != nil {
			return fmt.Errorf("failed to remove pre-push hook: %w", err)
		}
		fmt.Printf("✅ Removed: %s\n", prePushPath)
		prePushRemoved = true
	}

	if !preCommitRemoved && !prePushRemoved {
		return fmt.Errorf("no hooks found to uninstall")
	}

	fmt.Println()
	fmt.Println("🎉 Git hooks removed successfully!")

	return nil
}

// createPreCommitHook creates the pre-commit hook script
func createPreCommitHook(hookPath string) error {
	script := `#!/bin/bash
# DevSecOps Kit - Pre-commit Hook
# Blocks commits if security issues exceed configured thresholds

set -e

echo "🔍 Running security checks before commit..."
echo ""

# Run devsecops scan with threshold enforcement
if ! devsecops scan --fail-on-threshold; then
	echo ""
	echo "❌ Commit blocked due to security issues."
	echo "   Please review the findings above and remediate before retrying."
	echo ""
	exit 1
fi

echo ""
echo "✅ Security checks passed!"
exit 0
`

	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("failed to create pre-commit hook: %w", err)
	}

	return nil
}

// createPrePushHook creates the pre-push hook script (warning-only)
func createPrePushHook(hookPath string) error {
	script := `#!/bin/bash
# DevSecOps Kit - Pre-push Hook
# Warns about security issues but allows push to proceed

set -e

echo "🔍 Scanning for security issues before push..."
echo ""

# Run devsecops scan (without --fail-on-threshold to allow push)
if devsecops scan; then
	echo ""
	echo "✅ No blocking security issues detected!"
else
	# Scan ran but found issues below thresholds
	echo ""
	echo "⚠️  Review the findings above. Consider addressing them."
	echo "   (This is a warning only - push will proceed)"
fi

exit 0
`

	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("failed to create pre-push hook: %w", err)
	}

	return nil
}

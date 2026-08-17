// cli/cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Build metadata is set at build time via -ldflags.
	version = "development"
	commit  = "none"
	date    = "unknown"

	rootCmd = &cobra.Command{
		Use:   "devsecops",
		Short: "DevSecOps Kit - generate security pipelines for your project",
		Long: `DevSecOps Kit

An opinionated CLI that detects your project type and generates
GitHub Actions workflows and configuration for security scanning.`,
	}
)

// Execute runs the root command.
// This is called from cmd/devsecops/main.go
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// Version subcommand
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			printVersion()
		},
	})
}

func printVersion() {
	fmt.Fprintln(os.Stdout, "DevSecOps Kit")

	if commit == "none" && date == "unknown" {
		fmt.Fprintf(os.Stdout, "Version: %s\n", version)
		return
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Version : %s\n", version)
	fmt.Fprintf(os.Stdout, "Commit  : %s\n", commit)
	fmt.Fprintf(os.Stdout, "Built   : %s\n", date)
}

// cli/cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// version is set at build time via -ldflags, default for dev builds.
	version = "0.1.0"

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
			fmt.Fprintf(os.Stdout, "DevSecOps Kit version %s\n", version)
		},
	})
}

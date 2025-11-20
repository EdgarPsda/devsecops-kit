// cli/cmd/detect.go
package cmd

import (
	"fmt"
	"os"

	"github.com/EdgarPsda/devsecops-kit/cli/detectors"
	"github.com/spf13/cobra"
)

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Detect project language and framework",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}

		fmt.Println("🔍 Detecting project type in:", dir)

		info, err := detectors.DetectProject(dir)
		if err != nil {
			return err
		}

		fmt.Println("✅ Detection result:")
		fmt.Printf("  Language:   %s\n", info.Language)
		fmt.Printf("  Framework:  %s\n", info.Framework)
		fmt.Printf("  Package:    %s\n", info.PackageFile)
		fmt.Printf("  RootDir:    %s\n", info.RootDir)
		fmt.Printf("  Dependencies detected: %d\n", len(info.Dependencies))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(detectCmd)
}

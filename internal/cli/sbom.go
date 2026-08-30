package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/sbom"
)

var sbomOutput string

var sbomCmd = &cobra.Command{
	Use:   "sbom [path]",
	Short: "Generate a CycloneDX SBOM",
	Long:  "Generate a Software Bill of Materials in CycloneDX JSON format from project lockfiles.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runSBOM,
}

func init() {
	sbomCmd.Flags().StringVarP(&sbomOutput, "output", "o", "sbom.json", "SBOM output file")
}

func runSBOM(cmd *cobra.Command, args []string) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	cfg, err := config.LoadFromDir(config.ConfigDirForTarget(absPath))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	sc := sbom.NewScanner(cfg)
	start := time.Now()
	result, err := sc.Generate(context.Background(), absPath)
	if err != nil {
		return fmt.Errorf("SBOM generation failed: %w", err)
	}

	if err := sc.WriteJSON(result.Document, sbomOutput); err != nil {
		return fmt.Errorf("failed to write SBOM: %w", err)
	}

	fmt.Printf("%s SBOM saved to %s\n", color.GreenString("✓"), sbomOutput)
	fmt.Printf("  Components: %d\n", len(result.Document.Components))
	fmt.Printf("  Lockfiles:  %d\n", result.FilesCount)
	fmt.Printf("  Duration:   %s\n", time.Since(start).Round(time.Millisecond))

	return nil
}

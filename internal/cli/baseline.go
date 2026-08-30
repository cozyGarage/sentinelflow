package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/baseline"
	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner"
)

var baselineOutput string

var baselineCmd = &cobra.Command{
	Use:   "baseline [path]",
	Short: "Generate a findings baseline file",
	Long: `Run a scan and save all current findings to a baseline file.
Subsequent scans will skip baselined findings when baseline is enabled in config.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBaseline,
}

func init() {
	baselineCmd.Flags().StringVarP(&baselineOutput, "output", "o", baseline.DefaultPath, "baseline output file")
}

func runBaseline(cmd *cobra.Command, args []string) error {
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
		cfg = config.Default()
	}

	engine := scanner.NewEngine(cfg)
	result, err := engine.Scan(context.Background(), absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	bl := baseline.Generate(result.Findings)
	if err := baseline.Save(baselineOutput, bl); err != nil {
		return fmt.Errorf("failed to save baseline: %w", err)
	}

	fmt.Printf("%s Baseline saved to %s (%d findings)\n",
		color.GreenString("✓"), baselineOutput, len(bl.Findings))
	fmt.Println()
	fmt.Println("Enable baseline filtering in .sentinelflow.yaml:")
	fmt.Println("  baseline:")
	fmt.Println("    enabled: true")
	fmt.Printf("    file: %s\n", baselineOutput)

	return nil
}

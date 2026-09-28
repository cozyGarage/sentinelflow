package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/reporter"
	"github.com/cozygarage/sentinelflow/internal/scanner/artifacts"
	"github.com/cozygarage/sentinelflow/internal/scanner/sbom"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func runScanSBOM(cmd *cobra.Command, cfg *config.Config, sbomPath string) error {
	abs, err := filepath.Abs(sbomPath)
	if err != nil {
		return api.ErrTool(err.Error())
	}
	sc := sbom.NewScanner(cfg)
	result, err := sc.ScanFile(context.Background(), abs)
	if err != nil {
		return api.ErrTool(fmt.Sprintf("SBOM scan failed: %v", err))
	}
	return emitScanResult(cmd, cfg, result)
}

func emitScanResult(cmd *cobra.Command, cfg *config.Config, result *api.ScanResult) error {
	format := outputFormat
	formatChanged := cmd.Flags().Changed("format") || rootCmd.PersistentFlags().Changed("format")
	if !formatChanged && cfg.Reporting.Format != "" {
		format = cfg.Reporting.Format
	}
	rep := reporter.New(cfg)
	report, err := rep.Generate(result, format)
	if err != nil {
		return api.ErrTool(err.Error())
	}
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
			return api.ErrTool(err.Error())
		}
		fmt.Printf("%s Report saved to %s\n", color.GreenString("✓"), outputFile)
	} else {
		fmt.Println(report)
	}
	printScanSummary(result)
	if shouldFail(result, cfg) {
		return api.ErrFindings("scan failed due to findings exceeding threshold")
	}
	return nil
}

var scanArtifactCmd = &cobra.Command{
	Use:   "scan-artifact [file|dir]",
	Short: "Scan a binary, archive, or dist directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		abs, err := filepath.Abs(args[0])
		if err != nil {
			return api.ErrTool(err.Error())
		}
		cfg, err := loadScanConfig(abs)
		if err != nil {
			return api.ErrTool(err.Error())
		}
		cfg.Scanners.Artifacts.Enabled = true
		sc := artifacts.NewScanner(cfg)
		res, err := sc.Scan(context.Background(), abs, nil)
		if err != nil {
			return api.ErrTool(err.Error())
		}
		result := &api.ScanResult{
			Findings: res.Findings,
			ScannerRuns: []api.ScannerRun{{
				Scanner: "artifacts", FilesCount: res.FilesCount, FindingsCount: len(res.Findings),
				Warnings: res.Warnings,
			}},
			Metadata: api.ScanMetadata{TargetPath: abs, SentinelFlowVersion: GetVersion()},
		}
		return emitScanResult(cmd, cfg, result)
	},
}

func init() {
	rootCmd.AddCommand(scanArtifactCmd)
}

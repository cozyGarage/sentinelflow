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
	format, err := resolveFormat(cmd, cfg)
	if err != nil {
		return api.ErrTool(err.Error())
	}
	rep := reporter.New(cfg)
	report, err := rep.Generate(result, format)
	if err != nil {
		return api.ErrTool(err.Error())
	}
	if outputFile != "" {
		if dir := filepath.Dir(outputFile); dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return api.ErrTool(err.Error())
			}
		}
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
	Long: `Scan a binary, archive, or dist directory (SCA, secrets, hardening, malware heuristics).

Exit codes match scan: 0 pass, 1 findings gate, 2 error, 3 timeout.

Examples:
  sentinelflow scan-artifact dist/
  sentinelflow scan-artifact ./sentinelflow --fail-on critical -f json -o artifact-scan.json`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
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
		if err := applyGateFlags(cfg); err != nil {
			return api.ErrTool(err.Error())
		}
		if _, err := resolveFormat(cmd, cfg); err != nil {
			return api.ErrTool(err.Error())
		}
		if err := cfg.Validate(); err != nil {
			return api.ErrTool(fmt.Sprintf("invalid configuration: %v", err))
		}
		timeout, err := cfg.ScanTimeoutDuration()
		if err != nil {
			return api.ErrTool(err.Error())
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		sc := artifacts.NewScanner(cfg)
		res, err := sc.Scan(ctx, abs, nil)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return api.ErrTimeout(fmt.Sprintf("artifact scan timed out after %s: %v", timeout, err))
			}
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
	scanArtifactCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	scanArtifactCmd.Flags().StringVar(&failOnSeverity, "fail-on", "", "fail if findings match severity (critical, high, medium, low, info)")
	scanArtifactCmd.Flags().StringVar(&scanTimeoutFlag, "timeout", "", "scan deadline (Go duration, e.g. 10m, 90s); overrides scan_timeout")
	rootCmd.AddCommand(scanArtifactCmd)
}

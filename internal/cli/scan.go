package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/reporter"
	"github.com/cozygarage/sentinelflow/internal/scanner"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

var (
	scanSecrets      bool
	scanIaC          bool
	scanDependencies bool
	scanAI           bool
	scanSAST         bool
	scanContainer    bool
	scanLicense      bool
	scanAll          bool
	scanPath         string
	outputFile       string
	failOnSeverity   string
	containerImage   string
	useBaseline      bool
	scanTimeoutFlag  string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan for security vulnerabilities",
	Long: `Perform security scanning on the specified path or current directory.

Available scanners:
  --secrets      Scan for leaked secrets and API keys
  --iac          Scan Infrastructure-as-Code files
  --deps         Scan dependencies for vulnerabilities
  --sast         Static application security testing (OWASP patterns)
  --container    Scan container images (requires Trivy)
  --license      Check dependency licenses against policy
  --all          Enable secrets/IaC/deps/SAST/license (not container or AI; use --container for Trivy)

Examples:
  sentinelflow scan
  sentinelflow scan ./src --secrets --iac
  sentinelflow scan --all --format sarif -o report.sarif
  sentinelflow scan --fail-on high`,
	RunE:         runScan,
	SilenceUsage: true, // gate failures and scan errors print the message without cobra Usage spam
}

func init() {
	scanCmd.Flags().BoolVar(&scanSecrets, "secrets", false, "scan for secrets")
	scanCmd.Flags().BoolVar(&scanIaC, "iac", false, "scan Infrastructure-as-Code")
	scanCmd.Flags().BoolVar(&scanDependencies, "deps", false, "scan dependencies")
	scanCmd.Flags().BoolVar(&scanSAST, "sast", false, "static application security testing")
	scanCmd.Flags().BoolVar(&scanContainer, "container", false, "scan container images")
	scanCmd.Flags().BoolVar(&scanLicense, "license", false, "check dependency licenses")
	scanCmd.Flags().StringVar(&containerImage, "container-image", "", "container image to scan")
	scanCmd.Flags().BoolVar(&useBaseline, "baseline", false, "apply baseline filtering")
	scanCmd.Flags().StringVar(&scanTimeoutFlag, "timeout", "", "scan deadline (Go duration, e.g. 10m, 90s); overrides scan_timeout")
	scanCmd.Flags().BoolVar(&scanAI, "ai", false, "AI-powered code review (not available in this release)")
	scanCmd.Flags().BoolVar(&scanAll, "all", false, "enable secrets, iac, deps, sast, and license (not container/AI)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	scanCmd.Flags().StringVar(&failOnSeverity, "fail-on", "", "fail if findings match severity (critical, high, medium, low)")
}

func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	// Determine scan path
	if len(args) > 0 {
		scanPath = args[0]
	} else {
		var err error
		scanPath, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		if verbose {
			fmt.Println(color.YellowString("⚠ No config file found, using defaults"))
		}
		cfg = config.Default()
	}

	// Apply CLI flags to config, then normalize/validate (including --fail-on).
	if err := applyScanFlags(cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Prefer config reporting format unless --format was explicitly set
	format := outputFormat
	formatChanged := cmd.Flags().Changed("format") || rootCmd.PersistentFlags().Changed("format")
	if !formatChanged && cfg.Reporting.Format != "" {
		format = cfg.Reporting.Format
	}

	// Create scanner engine
	engine := scanner.NewEngine(cfg)

	// Print scan header
	printScanHeader(absPath, cfg)

	timeout, err := cfg.ScanTimeoutDuration()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Run scan with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := engine.Scan(ctx, absPath)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("scan timed out after %s: %w", timeout, err)
		}
		return fmt.Errorf("scan failed: %w", err)
	}

	result.Metadata.SentinelFlowVersion = GetVersion()
	result.Duration = api.DurationMS(time.Since(startTime))

	// Generate report
	rep := reporter.New(cfg)
	report, err := rep.Generate(result, format)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Output report
	if outputFile != "" {
		if dir := filepath.Dir(outputFile); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
		}
		if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Printf("\n%s Report saved to %s\n", color.GreenString("✓"), outputFile)
	} else {
		fmt.Println(report)
	}

	// Print summary
	printScanSummary(result)

	if err := scannerErrors(result, cfg); err != nil {
		return err
	}

	// Check fail conditions
	if shouldFail(result, cfg) {
		return fmt.Errorf("scan failed due to findings exceeding threshold")
	}

	return nil
}

func applyScanFlags(cfg *config.Config) error {
	if scanAI {
		return fmt.Errorf("%s", config.AINotAvailableMessage)
	}

	if scanAll {
		cfg.Scanners.Secrets.Enabled = true
		cfg.Scanners.IaC.Enabled = true
		cfg.Scanners.Dependencies.Enabled = true
		cfg.Scanners.SAST.Enabled = true
		cfg.Scanners.License.Enabled = true
		// Container needs Trivy (+ usually an image); keep opt-in via --container.
		cfg.Scanners.Container.Enabled = false
		// AI scanner is not registered in v1.0
		cfg.Scanners.AI.Enabled = false
	} else if scanSecrets || scanIaC || scanDependencies || scanSAST || scanContainer || scanLicense {
		// If specific flags are set, only enable those (including disabling policy —
		// defaults leave policies.enabled=true and would otherwise still run OPA).
		cfg.Scanners.Secrets.Enabled = scanSecrets
		cfg.Scanners.IaC.Enabled = scanIaC
		cfg.Scanners.Dependencies.Enabled = scanDependencies
		cfg.Scanners.AI.Enabled = false
		cfg.Scanners.SAST.Enabled = scanSAST
		cfg.Scanners.Container.Enabled = scanContainer
		cfg.Scanners.License.Enabled = scanLicense
		cfg.Policies.Enabled = false
	}

	if containerImage != "" {
		cfg.Scanners.Container.Enabled = true
		cfg.Scanners.Container.Image = containerImage
	}

	if useBaseline {
		cfg.Baseline.Enabled = true
	}

	if scanTimeoutFlag != "" {
		cfg.ScanTimeout = scanTimeoutFlag
	}

	// Override fail-on severity
	if failOnSeverity != "" {
		cfg.FailOn.Severity = failOnSeverity
	}

	return nil
}

func scannerErrors(result *api.ScanResult, cfg *config.Config) error {
	var errs []string
	for _, run := range result.ScannerRuns {
		if run.Error == "" {
			continue
		}
		if run.Scanner == "dependencies" && cfg != nil && !cfg.DependenciesFailOnError() {
			fmt.Printf("%s dependencies scanner error (non-fatal): %s\n", color.YellowString("⚠"), run.Error)
			continue
		}
		errs = append(errs, fmt.Sprintf("%s: %s", run.Scanner, run.Error))
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("one or more scanners failed:\n  - %s", strings.Join(errs, "\n  - "))
}

func printScanHeader(path string, cfg *config.Config) {
	if !verbose {
		return
	}

	fmt.Printf("📂 Scanning: %s\n", color.CyanString(path))
	fmt.Printf("📋 Scanners: ")

	scanners := []string{}
	if cfg.Scanners.Secrets.Enabled {
		scanners = append(scanners, "secrets")
	}
	if cfg.Scanners.IaC.Enabled {
		scanners = append(scanners, "iac")
	}
	if cfg.Scanners.Dependencies.Enabled {
		scanners = append(scanners, "dependencies")
	}
	if cfg.Scanners.SAST.Enabled {
		scanners = append(scanners, "sast")
	}
	if cfg.Scanners.Container.Enabled {
		scanners = append(scanners, "container")
	}
	if cfg.Scanners.License.Enabled {
		scanners = append(scanners, "license")
	}
	if cfg.Scanners.AI.Enabled {
		scanners = append(scanners, "ai")
	}

	for i, s := range scanners {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(color.GreenString(s))
	}
	fmt.Println()
	fmt.Println()
}

func printScanSummary(result *api.ScanResult) {
	fmt.Println()
	fmt.Println(color.CyanString("─────────────────────────────────────────────"))
	fmt.Println(color.CyanString("                  SUMMARY                    "))
	fmt.Println(color.CyanString("─────────────────────────────────────────────"))
	fmt.Println()

	counts := result.CountBySeverity()

	if counts[api.SeverityCritical] > 0 {
		fmt.Printf("  %s Critical: %d\n", color.RedString("●"), counts[api.SeverityCritical])
	}
	if counts[api.SeverityHigh] > 0 {
		fmt.Printf("  %s High:     %d\n", color.RedString("●"), counts[api.SeverityHigh])
	}
	if counts[api.SeverityMedium] > 0 {
		fmt.Printf("  %s Medium:   %d\n", color.YellowString("●"), counts[api.SeverityMedium])
	}
	if counts[api.SeverityLow] > 0 {
		fmt.Printf("  %s Low:      %d\n", color.BlueString("●"), counts[api.SeverityLow])
	}
	if counts[api.SeverityInfo] > 0 {
		fmt.Printf("  %s Info:     %d\n", color.WhiteString("●"), counts[api.SeverityInfo])
	}

	fmt.Println()
	fmt.Printf("  Total findings: %d\n", len(result.Findings))
	fmt.Printf("  Scan duration:  %s\n", result.Duration.Std().Round(time.Millisecond))

	if len(result.Findings) == 0 {
		fmt.Println()
		fmt.Println(color.GreenString("  ✓ No security issues found!"))
	}
}

func shouldFail(result *api.ScanResult, cfg *config.Config) bool {
	counts := result.CountBySeverity()

	threshold := strings.ToLower(strings.TrimSpace(cfg.FailOn.Severity))
	if threshold != "" {
		switch threshold {
		case "critical":
			if counts[api.SeverityCritical] > 0 {
				return true
			}
		case "high":
			if counts[api.SeverityCritical] > 0 || counts[api.SeverityHigh] > 0 {
				return true
			}
		case "medium":
			if counts[api.SeverityCritical] > 0 || counts[api.SeverityHigh] > 0 || counts[api.SeverityMedium] > 0 {
				return true
			}
		case "low":
			if counts[api.SeverityCritical] > 0 || counts[api.SeverityHigh] > 0 ||
				counts[api.SeverityMedium] > 0 || counts[api.SeverityLow] > 0 {
				return true
			}
		case "info":
			if len(result.Findings) > 0 {
				return true
			}
		}
	}

	if cfg.FailOn.Secrets {
		for _, f := range result.Findings {
			if f.Type == api.FindingTypeSecret {
				return true
			}
		}
	}

	if cfg.FailOn.PolicyViolations {
		for _, f := range result.Findings {
			if f.Type == api.FindingTypePolicyViolation {
				return true
			}
		}
	}

	return false
}

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/reporter"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate and manage security reports",
	Long:  "Commands for generating, converting, and managing security reports",
}

var reportConvertCmd = &cobra.Command{
	Use:   "convert [input] [output-format]",
	Short: "Convert report between formats",
	Long: `Convert a SentinelFlow report to different formats.

Supported formats:
  - json     JSON format
  - sarif    SARIF 2.1.0 format (for GitHub Security)
  - markdown Markdown format (for PR comments)
  - html     HTML format

Examples:
  sentinelflow report convert report.json sarif -o report.sarif
  sentinelflow report convert report.json markdown`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputFile := args[0]
		targetFormat := args[1]

		// Read input file
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		// Parse as scan result
		var result api.ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse input file: %w", err)
		}

		// Generate report in target format
		rep := reporter.New(nil)
		output, err := rep.Generate(&result, targetFormat)
		if err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}

		// Output
		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
			fmt.Printf("%s Report saved to %s\n", color.GreenString("✓"), outputPath)
		} else {
			fmt.Println(output)
		}

		return nil
	},
}

var reportMergeCmd = &cobra.Command{
	Use:   "merge [files...]",
	Short: "Merge multiple reports into one",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		var merged api.ScanResult
		merged.Findings = []api.Finding{}

		for _, file := range args {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", file, err)
			}

			var result api.ScanResult
			if err := json.Unmarshal(data, &result); err != nil {
				return fmt.Errorf("failed to parse %s: %w", file, err)
			}

			merged.Findings = append(merged.Findings, result.Findings...)
		}

		// Deduplicate findings
		merged.Findings = deduplicateFindings(merged.Findings)

		// Output merged report
		outputPath, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")

		rep := reporter.New(nil)
		output, err := rep.Generate(&merged, format)
		if err != nil {
			return fmt.Errorf("failed to generate merged report: %w", err)
		}

		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
			fmt.Printf("%s Merged %d reports with %d total findings\n",
				color.GreenString("✓"), len(args), len(merged.Findings))
		} else {
			fmt.Println(output)
		}

		return nil
	},
}

func deduplicateFindings(findings []api.Finding) []api.Finding {
	type findingKey struct {
		id        string
		file      string
		startLine int
	}

	seen := make(map[findingKey]struct{}, len(findings))
	result := make([]api.Finding, 0, len(findings))

	for _, f := range findings {
		key := findingKey{id: f.ID, file: f.Location.File, startLine: f.Location.StartLine}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, f)
	}

	return result
}

func init() {
	reportConvertCmd.Flags().StringP("output", "o", "", "output file path")
	reportMergeCmd.Flags().StringP("output", "o", "", "output file path")
	reportMergeCmd.Flags().StringP("format", "f", "json", "output format")

	reportCmd.AddCommand(reportConvertCmd)
	reportCmd.AddCommand(reportMergeCmd)
}

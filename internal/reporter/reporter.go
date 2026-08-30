// Package reporter provides report generation in various formats
package reporter

import (
	"fmt"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Reporter generates security scan reports
type Reporter struct {
	config     *config.Config
	formatters map[string]Formatter
}

// Formatter defines the interface for report formatters
type Formatter interface {
	Format(result *api.ScanResult) (string, error)
}

// New creates a new reporter
func New(cfg *config.Config) *Reporter {
	r := &Reporter{
		config:     cfg,
		formatters: make(map[string]Formatter),
	}

	// Register formatters
	r.formatters["text"] = &TextFormatter{}
	r.formatters["markdown"] = &MarkdownFormatter{}
	r.formatters["json"] = &JSONFormatter{}
	r.formatters["sarif"] = &SARIFFormatter{}
	r.formatters["html"] = &HTMLFormatter{}

	return r
}

// Generate generates a report in the specified format
func (r *Reporter) Generate(result *api.ScanResult, format string) (string, error) {
	formatter, exists := r.formatters[format]
	if !exists {
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	// Defense-in-depth: never emit raw secret-like snippets in any format.
	return formatter.Format(redactResult(result))
}

func redactResult(result *api.ScanResult) *api.ScanResult {
	if result == nil {
		return nil
	}
	out := *result
	if len(result.Findings) == 0 {
		return &out
	}
	out.Findings = make([]api.Finding, len(result.Findings))
	copy(out.Findings, result.Findings)
	for i := range out.Findings {
		f := &out.Findings[i]
		if f.Type == api.FindingTypeSecret || f.Scanner == "secrets" {
			f.Location.Snippet = redact.Snippet(f.Location.Snippet)
			if f.Title != "" {
				f.Title = redact.Line(f.Title)
			}
			if f.Description != "" {
				f.Description = redact.Line(f.Description)
			}
		} else if f.Location.Snippet != "" {
			// Soft redact assignment-like values in other scanners too.
			f.Location.Snippet = redact.Snippet(f.Location.Snippet)
		}
	}
	return &out
}

// TextFormatter formats reports as plain text
type TextFormatter struct{}

func (f *TextFormatter) Format(result *api.ScanResult) (string, error) {
	var output string

	output += "=====================================\n"
	output += "  SentinelFlow Security Scan Report\n"
	output += "=====================================\n\n"

	output += fmt.Sprintf("Target:   %s\n", result.Metadata.TargetPath)
	output += fmt.Sprintf("Started:  %s\n", result.Metadata.StartTime.Format("2006-01-02 15:04:05"))
	output += fmt.Sprintf("Duration: %s\n", result.Duration.Std())
	output += fmt.Sprintf("Scanners: %d\n\n", len(result.ScannerRuns))

	// Summary by severity
	counts := result.CountBySeverity()
	output += "Findings by Severity:\n"
	output += fmt.Sprintf("  Critical: %d\n", counts[api.SeverityCritical])
	output += fmt.Sprintf("  High:     %d\n", counts[api.SeverityHigh])
	output += fmt.Sprintf("  Medium:   %d\n", counts[api.SeverityMedium])
	output += fmt.Sprintf("  Low:      %d\n", counts[api.SeverityLow])
	output += fmt.Sprintf("  Info:     %d\n", counts[api.SeverityInfo])
	output += fmt.Sprintf("\nTotal Findings: %d\n\n", len(result.Findings))

	// Scanner results
	output += "Scanner Results:\n"
	for _, run := range result.ScannerRuns {
		status := "✓"
		if run.Error != "" {
			status = "✗"
		}
		output += fmt.Sprintf("  %s %s - %d findings in %s\n",
			status, run.Scanner, run.FindingsCount, run.Duration.Std())
	}

	if len(result.Findings) > 0 {
		output += "\n=====================================\n"
		output += "  Detailed Findings\n"
		output += "=====================================\n\n"

		// Group by severity
		for _, severity := range []api.Severity{
			api.SeverityCritical,
			api.SeverityHigh,
			api.SeverityMedium,
			api.SeverityLow,
			api.SeverityInfo,
		} {
			findings := result.FilterBySeverity(severity)
			if len(findings) == 0 {
				continue
			}

			output += fmt.Sprintf("\n%s (%d)\n", severity, len(findings))
			output += "-----------------------------------\n\n"

			for _, finding := range findings {
				output += fmt.Sprintf("[%s] %s\n", finding.RuleID, finding.Title)
				output += fmt.Sprintf("  File: %s:%d\n", finding.Location.File, finding.Location.StartLine)
				output += fmt.Sprintf("  %s\n", finding.Description)
				if finding.Remediation != "" {
					output += fmt.Sprintf("  Fix: %s\n", finding.Remediation)
				}
				output += "\n"
			}
		}
	}

	return output, nil
}

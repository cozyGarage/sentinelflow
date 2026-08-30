package reporter

import (
	"encoding/json"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// SARIFFormatter formats reports in SARIF format for GitHub Security tab
type SARIFFormatter struct{}

func (f *SARIFFormatter) Format(result *api.ScanResult) (string, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return "", err
	}

	// Create a single run for SentinelFlow
	run := sarif.NewRunWithInformationURI(
		"SentinelFlow",
		"https://github.com/cozygarage/sentinelflow",
	)
	run.Tool.Driver.Version = &result.Metadata.SentinelFlowVersion
	run.Tool.Driver.Name = "SentinelFlow"

	report.AddRun(run)

	// Add findings
	for _, finding := range result.Findings {
		// Create rule if not exists
		ruleID := finding.RuleID
		if ruleID == "" {
			ruleID = finding.ID
		}

		rule := run.AddRule(ruleID)
		rule.ShortDescription = &sarif.MultiformatMessageString{
			Text: &finding.Title,
		}
		rule.FullDescription = &sarif.MultiformatMessageString{
			Text: &finding.Description,
		}

		// Add remediation if available
		if finding.Remediation != "" {
			rule.Help = &sarif.MultiformatMessageString{
				Text: &finding.Remediation,
			}
		}

		// Create result (finding)
		sarifResult := sarif.NewRuleResult(ruleID)
		messageText := finding.Description
		sarifResult.Message = sarif.Message{
			Text: &messageText,
		}
		level := f.severityToLevel(finding.Severity)
		sarifResult.Level = &level

		// Add location
		if finding.Location.File != "" {
			location := sarif.NewPhysicalLocation()
			location.ArtifactLocation = &sarif.ArtifactLocation{
				URI: &finding.Location.File,
			}

			if finding.Location.StartLine > 0 {
				region := sarif.NewRegion()
				startLine := finding.Location.StartLine
				endLine := finding.Location.EndLine
				region.StartLine = &startLine
				region.EndLine = &endLine

				if finding.Location.Snippet != "" {
					region.Snippet = &sarif.ArtifactContent{
						Text: &finding.Location.Snippet,
					}
				}

				location.Region = region
			}

			sarifResult.Locations = []*sarif.Location{
				{PhysicalLocation: location},
			}
		}

		// Add properties
		properties := map[string]interface{}{
			"confidence": finding.Confidence,
			"scanner":    finding.Scanner,
			"type":       finding.Type,
		}

		if finding.CVE != "" {
			properties["cve"] = finding.CVE
		}
		if finding.CVSS > 0 {
			properties["cvss"] = finding.CVSS
		}

		propertyBag := sarif.NewPropertyBag()
		for k, v := range properties {
			propertyBag.Add(k, v)
		}
		sarifResult.PropertyBag = *propertyBag

		run.AddResult(sarifResult)
	}

	// Convert to JSON
	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (f *SARIFFormatter) severityToLevel(severity api.Severity) string {
	switch severity {
	case api.SeverityCritical, api.SeverityHigh:
		return "error"
	case api.SeverityMedium:
		return "warning"
	case api.SeverityLow, api.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

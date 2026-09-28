package reporter

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const repositoryURL = "https://github.com/cozyGarage/sentinelflow"

// SARIFFormatter formats reports in SARIF 2.1.0 for GitHub code scanning.
type SARIFFormatter struct{}

func (f *SARIFFormatter) Format(result *api.ScanResult) (string, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return "", err
	}

	run := sarif.NewRunWithInformationURI(
		"SentinelFlow",
		repositoryURL,
	)
	run.Tool.Driver.Version = &result.Metadata.SentinelFlowVersion
	run.Tool.Driver.Name = "SentinelFlow"
	run.Tool.Driver.InformationURI = strPtr(repositoryURL)

	baseID := "REPO_ROOT"
	baseURI := result.Metadata.TargetPath
	if baseURI == "" {
		baseURI = "."
	}
	run.OriginalUriBaseIDs = map[string]*sarif.ArtifactLocation{
		baseID: {
			URI: strPtr(toFileURI(baseURI)),
		},
	}
	autoID := "sentinelflow/" + strings.TrimPrefix(result.Metadata.SentinelFlowVersion, "v")
	run.AutomationDetails = &sarif.RunAutomationDetails{ID: &autoID}

	inv := sarif.NewInvocation()
	ok := true
	inv.ExecutionSuccessful = &ok
	for _, sr := range result.ScannerRuns {
		if sr.Error == "" {
			continue
		}
		level := "error"
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, &sarif.Notification{
			Level: level,
			Message: &sarif.Message{
				Text: strPtr(sr.Scanner + ": " + sr.Error),
			},
		})
	}
	for _, skip := range result.Skipped {
		level := "warning"
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, &sarif.Notification{
			Level: level,
			Message: &sarif.Message{
				Text: strPtr("skipped " + skip.Path + " (" + skip.Reason + ")"),
			},
		})
	}
	run.Invocations = []*sarif.Invocation{inv}

	report.AddRun(run)

	for _, finding := range result.Findings {
		ruleID := finding.RuleID
		if ruleID == "" {
			ruleID = finding.ID
		}

		rule := run.AddRule(ruleID)
		rule.ShortDescription = &sarif.MultiformatMessageString{Text: &finding.Title}
		rule.FullDescription = &sarif.MultiformatMessageString{Text: &finding.Description}
		if finding.Remediation != "" {
			rule.Help = &sarif.MultiformatMessageString{Text: &finding.Remediation}
		}
		rule.Properties = sarif.Properties{
			"security-severity": securitySeverity(finding),
			"tags":              append(append([]string{"security", finding.Scanner}, finding.CWE...), finding.OWASP...),
		}

		sarifResult := sarif.NewRuleResult(ruleID)
		messageText := finding.Description
		sarifResult.Message = sarif.Message{Text: &messageText}
		level := f.severityToLevel(finding.Severity)
		sarifResult.Level = &level

		fp := finding.Fingerprint
		if fp == "" {
			fp = finding.ID
		}
		sarifResult.PartialFingerprints = map[string]interface{}{
			"primaryLocationLineHash": fp,
		}

		if finding.Location.File != "" {
			location := sarif.NewPhysicalLocation()
			uri := filepath.ToSlash(finding.Location.File)
			location.ArtifactLocation = &sarif.ArtifactLocation{
				URI:       &uri,
				URIBaseId: strPtr(baseID),
			}
			if finding.Location.StartLine > 0 {
				region := sarif.NewRegion()
				startLine := finding.Location.StartLine
				endLine := finding.Location.EndLine
				region.StartLine = &startLine
				region.EndLine = &endLine
				if finding.Location.Snippet != "" {
					region.Snippet = &sarif.ArtifactContent{Text: &finding.Location.Snippet}
				}
				location.Region = region
			}
			loc := &sarif.Location{PhysicalLocation: location}
			if finding.Location.ArtifactPath != "" {
				logical := finding.Location.ArtifactPath
				kind := "artifact"
				loc.LogicalLocations = []*sarif.LogicalLocation{{
					FullyQualifiedName: &logical,
					Kind:               &kind,
				}}
			}
			sarifResult.Locations = []*sarif.Location{loc}
		}

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
		if finding.Fingerprint != "" {
			properties["fingerprint"] = finding.Fingerprint
		}
		propertyBag := sarif.NewPropertyBag()
		for k, v := range properties {
			propertyBag.Add(k, v)
		}
		sarifResult.PropertyBag = *propertyBag

		run.AddResult(sarifResult)
	}

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

func securitySeverity(f api.Finding) string {
	if f.CVSS > 0 {
		return strconv.FormatFloat(f.CVSS, 'f', 1, 64)
	}
	switch f.Severity {
	case api.SeverityCritical:
		return "9.5"
	case api.SeverityHigh:
		return "8.0"
	case api.SeverityMedium:
		return "5.5"
	case api.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

func strPtr(s string) *string { return &s }

func toFileURI(path string) string {
	p := filepath.ToSlash(path)
	if strings.HasPrefix(p, "/") {
		return "file://" + p
	}
	return p
}

package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// GitLabSASTFormatter emits GitLab gl-sast-report.json (schema 15).
type GitLabSASTFormatter struct{}

func (f *GitLabSASTFormatter) Format(result *api.ScanResult) (string, error) {
	type loc struct {
		File  string `json:"file"`
		Start struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
	}
	type ident struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type vuln struct {
		ID          string  `json:"id"`
		Category    string  `json:"category"`
		Name        string  `json:"name"`
		Message     string  `json:"message"`
		Description string  `json:"description"`
		Severity    string  `json:"severity"`
		Location    loc     `json:"location"`
		Identifiers []ident `json:"identifiers"`
	}
	doc := map[string]any{
		"version": "15.0.4",
		"scan": map[string]any{
			"analyzer": map[string]any{
				"id": "sentinelflow", "name": "SentinelFlow",
				"version": result.Metadata.SentinelFlowVersion,
			},
			"scanner": map[string]any{
				"id": "sentinelflow", "name": "SentinelFlow",
				"version": result.Metadata.SentinelFlowVersion,
			},
			"type":       "sast",
			"start_time": result.Metadata.StartTime.UTC().Format("2006-01-02T15:04:05"),
			"end_time":   result.Metadata.EndTime.UTC().Format("2006-01-02T15:04:05"),
			"status":     "success",
		},
	}
	var vulns []vuln
	for _, finding := range result.Findings {
		if finding.Type == api.FindingTypeVulnerability {
			continue
		}
		v := vuln{
			ID:          firstNonEmpty(finding.Fingerprint, finding.ID),
			Category:    "sast",
			Name:        finding.Title,
			Message:     finding.Title,
			Description: finding.Description,
			Severity:    strings.ToUpper(string(finding.Severity)),
		}
		v.Location.File = finding.Location.File
		v.Location.Start.Line = finding.Location.StartLine
		v.Location.End.Line = finding.Location.EndLine
		if finding.RuleID != "" {
			v.Identifiers = append(v.Identifiers, ident{Type: "sentinelflow_rule_id", Name: finding.RuleID, Value: finding.RuleID})
		}
		for _, cwe := range finding.CWE {
			v.Identifiers = append(v.Identifiers, ident{Type: "cwe", Name: cwe, Value: strings.TrimPrefix(cwe, "CWE-")})
		}
		vulns = append(vulns, v)
	}
	doc["vulnerabilities"] = vulns
	b, err := json.MarshalIndent(doc, "", "  ")
	return string(b), err
}

// GitLabDepsFormatter emits GitLab gl-dependency-scanning-report.json.
type GitLabDepsFormatter struct{}

func (f *GitLabDepsFormatter) Format(result *api.ScanResult) (string, error) {
	sast := &GitLabSASTFormatter{}
	raw, err := sast.Format(result)
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return "", err
	}
	if scan, ok := doc["scan"].(map[string]any); ok {
		scan["type"] = "dependency_scanning"
	}
	var vulns []any
	for _, finding := range result.Findings {
		if finding.Type != api.FindingTypeVulnerability && finding.Type != api.FindingTypeComponent {
			continue
		}
		vulns = append(vulns, map[string]any{
			"id":          firstNonEmpty(finding.Fingerprint, finding.ID),
			"category":    "dependency_scanning",
			"name":        finding.Title,
			"message":     finding.Title,
			"description": finding.Description,
			"severity":    strings.ToUpper(string(finding.Severity)),
			"location": map[string]any{
				"file": finding.Location.File,
			},
			"identifiers": []map[string]string{{
				"type": "cve", "name": firstNonEmpty(finding.CVE, finding.RuleID),
				"value": firstNonEmpty(finding.CVE, finding.RuleID),
			}},
		})
	}
	doc["vulnerabilities"] = vulns
	b, err := json.MarshalIndent(doc, "", "  ")
	return string(b), err
}

// JUnitFormatter emits a JUnit XML suite (one testcase per finding).
type JUnitFormatter struct{}

func (f *JUnitFormatter) Format(result *api.ScanResult) (string, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&b, `<testsuite name="sentinelflow" tests="%d" failures="%d" time="%.3f">`+"\n",
		len(result.Findings), len(result.Findings), result.Duration.Std().Seconds())
	if len(result.Findings) == 0 {
		b.WriteString(`  <testcase name="no findings" classname="sentinelflow"/>` + "\n")
	}
	for _, finding := range result.Findings {
		name := xmlEscape(finding.RuleID + " " + finding.Title)
		class := xmlEscape(finding.Location.File)
		fmt.Fprintf(&b, `  <testcase name="%s" classname="%s">`+"\n", name, class)
		fmt.Fprintf(&b, `    <failure message="%s" type="%s">%s</failure>`+"\n",
			xmlEscape(finding.Title), xmlEscape(string(finding.Severity)), xmlEscape(finding.Description))
		b.WriteString("  </testcase>\n")
	}
	b.WriteString("</testsuite>\n")
	return b.String(), nil
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// GitHubAnnotations returns workflow command annotations for findings.
func GitHubAnnotations(result *api.ScanResult) string {
	var b strings.Builder
	for _, f := range result.Findings {
		level := "warning"
		if f.Severity == api.SeverityCritical || f.Severity == api.SeverityHigh {
			level = "error"
		}
		fmt.Fprintf(&b, "::%s file=%s,line=%d::%s: %s\n",
			level, f.Location.File, f.Location.StartLine, f.RuleID, strings.ReplaceAll(f.Title, "\n", " "))
	}
	return b.String()
}

// AppendGitHubSummary appends a markdown summary to $GITHUB_STEP_SUMMARY.
func AppendGitHubSummary(path string, result *api.ScanResult) error {
	md, err := (&MarkdownFormatter{}).Format(result)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(md + "\n")
	return err
}

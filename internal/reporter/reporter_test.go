package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func createTestResult() *api.ScanResult {
	return &api.ScanResult{
		Findings: []api.Finding{
			{
				ID:          "SEC-001",
				Type:        api.FindingTypeSecret,
				Severity:    api.SeverityCritical,
				Title:       "Hardcoded AWS Access Key",
				Description: "Found AWS access key in source code",
				Location:    api.Location{File: "config.go", StartLine: 10, EndLine: 10},
				Remediation: "Remove hardcoded credentials and use environment variables",
				Scanner:     "secrets",
				RuleID:      "aws-access-key",
				Confidence:  0.95,
			},
			{
				ID:          "IAC-001",
				Type:        api.FindingTypeMisconfiguration,
				Severity:    api.SeverityHigh,
				Title:       "Public S3 Bucket",
				Description: "S3 bucket has public read ACL",
				Location:    api.Location{File: "main.tf", StartLine: 15, EndLine: 18},
				Remediation: "Set ACL to 'private'",
				Scanner:     "iac",
				RuleID:      "aws-s3-public-acl",
				Confidence:  1.0,
			},
		},
		ScannerRuns: []api.ScannerRun{
			{
				Scanner:       "secrets",
				StartTime:     time.Now().Add(-2 * time.Minute),
				EndTime:       time.Now().Add(-1 * time.Minute),
				Duration:      api.DurationMS(time.Minute),
				FilesCount:    10,
				FindingsCount: 1,
			},
			{
				Scanner:       "iac",
				StartTime:     time.Now().Add(-1 * time.Minute),
				EndTime:       time.Now(),
				Duration:      api.DurationMS(time.Minute),
				FilesCount:    5,
				FindingsCount: 1,
			},
		},
		Metadata: api.ScanMetadata{
			TargetPath:          "/path/to/project",
			StartTime:           time.Now().Add(-2 * time.Minute),
			EndTime:             time.Now(),
			SentinelFlowVersion: "1.0.0",
		},
		Duration: api.DurationMS(2 * time.Minute),
	}
}

func TestMarkdownFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &MarkdownFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Check for key sections
	if !strings.Contains(output, "# 🛡️ SentinelFlow Security Scan Report") {
		t.Error("Missing header")
	}

	if !strings.Contains(output, "## 📊 Summary") {
		t.Error("Missing summary section")
	}

	if !strings.Contains(output, "🔴 **Critical**: 1") {
		t.Error("Missing critical findings count")
	}

	if !strings.Contains(output, "🟠 **High**: 1") {
		t.Error("Missing high findings count")
	}

	// Check for findings
	if !strings.Contains(output, "Hardcoded AWS Access Key") {
		t.Error("Missing finding title")
	}

	if !strings.Contains(output, "Public S3 Bucket") {
		t.Error("Missing second finding")
	}
}

func TestMarkdownFormatterBaselineSummary(t *testing.T) {
	result := createTestResult()
	result.Baseline = &api.BaselineSummary{Enabled: true, Total: 5, Suppressed: 3, New: 2}

	output, err := (&MarkdownFormatter{}).Format(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "| **Baselined (suppressed)** | 3 |") {
		t.Fatalf("missing suppressed row:\n%s", output)
	}
	if !strings.Contains(output, "| **New findings** | **2** |") {
		t.Fatalf("missing new findings row:\n%s", output)
	}
	if !strings.Contains(output, "| **Total Findings** | **2** |") {
		t.Fatalf("total findings should stay the post-filter count:\n%s", output)
	}
}

func TestJSONFormatterIncludesBaselineSummary(t *testing.T) {
	result := createTestResult()
	result.Baseline = &api.BaselineSummary{Enabled: true, Total: 4, Suppressed: 2, New: 2}

	output, err := (&JSONFormatter{}).Format(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"baseline"`, `"suppressed": 2`, `"new": 2`, `"total": 4`} {
		if !strings.Contains(output, want) {
			t.Fatalf("JSON missing %s:\n%s", want, output)
		}
	}
}

func TestMarkdownFormatterEscapesUntrustedContent(t *testing.T) {
	result := createTestResult()
	result.Findings[0].Title = `<script>alert(1)</script>`
	result.Findings[0].Description = `Click [here](javascript:alert(1))`
	result.Findings[0].Location.File = "path|with|pipes.go"
	result.Findings[0].Location.Snippet = "secret := ```injected```"

	output, err := (&MarkdownFormatter{}).Format(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "<script>alert(1)</script>") {
		t.Fatal("expected HTML in titles to be escaped")
	}
	if strings.Contains(output, "```injected```") {
		t.Fatal("expected code fence breakout to be sanitized")
	}
	if !strings.Contains(output, "path|with|pipes.go") && !strings.Contains(output, "path\\|with\\|pipes.go") {
		// file is inline-code escaped; pipes in backticks are fine
		t.Fatal("expected file path to remain readable")
	}
}

func TestJSONFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &JSONFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Should be valid JSON
	if !strings.HasPrefix(output, "{") {
		t.Error("Output is not JSON")
	}

	if !strings.Contains(output, `"findings"`) {
		t.Error("Missing findings field")
	}
	if !strings.Contains(output, `"duration_ms"`) {
		t.Error("Missing duration_ms field")
	}

	if !strings.Contains(output, `"SEC-001"`) {
		t.Error("Missing finding ID")
	}
}

func TestHTMLFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &HTMLFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Check for HTML structure
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE")
	}

	if !strings.Contains(output, "<html") {
		t.Error("Missing HTML tag")
	}

	if !strings.Contains(output, "SentinelFlow Security Report") {
		t.Error("Missing title")
	}

	// Check for findings
	if !strings.Contains(output, "Hardcoded AWS Access Key") {
		t.Error("Missing finding in HTML")
	}

	// Check for CSS
	if !strings.Contains(output, "<style>") {
		t.Error("Missing embedded CSS")
	}
}

func TestTextFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Check for key sections
	if !strings.Contains(output, "SentinelFlow Security Scan Report") {
		t.Error("Missing header")
	}

	if !strings.Contains(output, "Total Findings: 2") {
		t.Error("Missing total findings count")
	}

	if !strings.Contains(output, "Critical: 1") {
		t.Error("Missing critical count")
	}

	if !strings.Contains(output, "High:     1") {
		t.Error("Missing high count")
	}
}

func TestSARIFHasFingerprintsAndSecuritySeverity(t *testing.T) {
	result := createTestResult()
	result.Findings[0].Fingerprint = "abc123"
	result.Findings[0].CWE = []string{"CWE-798"}
	result.Findings[0].CVSS = 9.1
	result.ScannerRuns[0].Error = "partial"
	output, err := (&SARIFFormatter{}).Format(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"partialFingerprints", "security-severity", "CWE-798", "automationDetails",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("SARIF missing %s", want)
		}
	}
}

func TestSARIFSchemaAndGolden(t *testing.T) {
	result := createTestResult()
	result.Findings[0].Fingerprint = "fp-secret"
	result.Findings[0].CWE = []string{"CWE-798"}
	result.Findings[0].OWASP = []string{"A07:2021"}
	result.Findings[1].Fingerprint = "fp-iac"
	result.Findings[1].CWE = []string{"CWE-732"}
	result.Skipped = []api.SkippedFile{{Path: "big.bin", Reason: "exceeds max_file_size"}}
	result.ScannerRuns[0].Error = "partial"
	result.Metadata.TargetPath = "/repo"
	result.Metadata.StartTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	result.Metadata.EndTime = time.Date(2026, 1, 2, 3, 5, 5, 0, time.UTC)

	output, err := (&SARIFFormatter{}).Format(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(output), &doc); err != nil {
		t.Fatal(err)
	}
	validateSARIF210(t, doc)

	goldenPath := filepath.Join("testdata", "sarif-golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, prettyJSON(t, doc), 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("golden missing (%v); run UPDATE_GOLDEN=1 go test ./internal/reporter -run TestSARIFSchemaAndGolden", err)
	}
	got := prettyJSON(t, doc)
	if string(got) != string(want) {
		t.Fatalf("SARIF golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func prettyJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func validateSARIF210(t *testing.T, doc map[string]any) {
	t.Helper()
	if doc["version"] != "2.1.0" {
		t.Fatalf("version=%v", doc["version"])
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) == 0 {
		t.Fatal("no runs")
	}
	run, _ := runs[0].(map[string]any)
	if run["automationDetails"] == nil {
		t.Fatal("missing automationDetails")
	}
	if run["originalUriBaseIds"] == nil {
		t.Fatal("missing originalUriBaseIds")
	}
	invs, _ := run["invocations"].([]any)
	if len(invs) == 0 {
		t.Fatal("missing invocations")
	}
	inv, _ := invs[0].(map[string]any)
	notes, _ := inv["toolExecutionNotifications"].([]any)
	if len(notes) == 0 {
		t.Fatal("expected toolExecutionNotifications for scanner error/skip")
	}
	results, _ := run["results"].([]any)
	if len(results) == 0 {
		t.Fatal("no results")
	}
	res0, _ := results[0].(map[string]any)
	if res0["partialFingerprints"] == nil {
		t.Fatal("missing partialFingerprints")
	}
	driver, _ := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules, _ := driver["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("missing rules")
	}
	rule, _ := rules[0].(map[string]any)
	props, _ := rule["properties"].(map[string]any)
	if props["security-severity"] == nil {
		t.Fatal("missing rule properties.security-severity")
	}
	if props["tags"] == nil {
		t.Fatal("missing rule properties.tags")
	}
}

func TestGitLabAndJUnitFormats(t *testing.T) {
	result := createTestResult()
	sastJSON, err := (&GitLabSASTFormatter{}).Format(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sastJSON, `"type": "sast"`) {
		t.Fatalf("gitlab sast: %s", sastJSON)
	}
	xml, err := (&JUnitFormatter{}).Format(result)
	if err != nil || !strings.Contains(xml, "<failure") {
		t.Fatalf("junit: %v %s", err, xml)
	}
	md, err := (&MarkdownFormatter{}).Format(result)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	p := filepath.Join(tmp, "summary.md")
	if err := AppendGitHubSummary(p, result); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "SentinelFlow") {
		t.Fatalf("summary: %s", md)
	}
}

func TestJUnitAndGitHubAnnotations(t *testing.T) {
	result := createTestResult()
	xml, err := (&JUnitFormatter{}).Format(result)
	if err != nil || !strings.Contains(xml, "<testsuite") {
		t.Fatalf("junit: %v %s", err, xml)
	}
	ann := GitHubAnnotations(result)
	if !strings.Contains(ann, "::error") {
		t.Fatalf("annotations: %s", ann)
	}
}

func TestSARIFFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &SARIFFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Should be valid JSON
	if !strings.HasPrefix(output, "{") {
		t.Error("Output is not JSON")
	}

	// Check for SARIF structure
	if !strings.Contains(output, `"version"`) {
		t.Error("Missing SARIF version")
	}

	if !strings.Contains(output, `"runs"`) {
		t.Error("Missing runs array")
	}

	if !strings.Contains(output, `"results"`) {
		t.Error("Missing results array")
	}

	if !strings.Contains(output, "SentinelFlow") {
		t.Error("Missing tool name")
	}
}

func TestGenerateRedactsSecretSnippets(t *testing.T) {
	result := createTestResult()
	result.Findings[0].Location.Snippet = `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`

	rep := New(nil)
	out, err := rep.Generate(result, "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "wJalrXUtnFEMI") {
		t.Fatalf("expected secret snippet redacted in JSON report, got snippet leak")
	}
	if !strings.Contains(out, "***REDACTED***") {
		t.Fatal("expected redaction marker in report")
	}
	// Original result must remain unchanged for callers that keep findings in memory.
	if !strings.Contains(result.Findings[0].Location.Snippet, "wJalrXUtnFEMI") {
		t.Fatal("Generate should not mutate the caller's ScanResult snippets")
	}
}

func TestGenerateRedactsSecretMetadata(t *testing.T) {
	result := createTestResult()
	result.Findings[0].Type = api.FindingTypeSecret
	result.Findings[0].Scanner = "secrets"
	result.Findings[0].Metadata = map[string]any{
		"raw":   `token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"`,
		"match": 0,
	}

	rep := New(nil)
	out, err := rep.Generate(result, "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD") {
		t.Fatal("expected secret metadata string redacted in JSON report")
	}
	if raw, ok := result.Findings[0].Metadata["raw"].(string); !ok || !strings.Contains(raw, "ghp_") {
		t.Fatal("Generate should not mutate caller's Metadata")
	}
}

func TestGenerateRedactsSecretRemediationAndReferences(t *testing.T) {
	result := createTestResult()
	result.Findings[0].Type = api.FindingTypeSecret
	result.Findings[0].Scanner = "secrets"
	result.Findings[0].Remediation = `rotate token="ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD" immediately`
	result.Findings[0].References = []string{`https://example.com?token=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD`}

	rep := New(nil)
	out, err := rep.Generate(result, "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD") {
		t.Fatal("expected remediation/references redacted in JSON report")
	}
}

func TestEmptyResults(t *testing.T) {
	result := &api.ScanResult{
		Findings:    []api.Finding{},
		ScannerRuns: []api.ScannerRun{},
		Metadata: api.ScanMetadata{
			TargetPath:          "/path/to/project",
			StartTime:           time.Now(),
			EndTime:             time.Now(),
			SentinelFlowVersion: "1.0.0",
		},
	}

	formatters := []Formatter{
		&TextFormatter{},
		&MarkdownFormatter{},
		&JSONFormatter{},
		&HTMLFormatter{},
		&SARIFFormatter{},
		&JUnitFormatter{},
		&GitLabSASTFormatter{},
	}

	for _, formatter := range formatters {
		_, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Formatter %T failed on empty result: %v", formatter, err)
		}
	}
}

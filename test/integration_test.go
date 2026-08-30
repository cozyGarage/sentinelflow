// Integration tests for SentinelFlow
//go:build integration
// +build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/reporter"
	"github.com/cozygarage/sentinelflow/internal/scanner"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// TestFullScanPipeline tests the entire scanning workflow end-to-end
func TestFullScanPipeline(t *testing.T) {
	// Create a temporary project with various security issues
	tmpDir := t.TempDir()

	// Create vulnerable Terraform file
	terraformContent := `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_db_instance" "default" {
  allocated_storage = 20
  storage_encrypted = false
  username          = "admin"
  password          = "hardcoded123"
}
`
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(terraformContent), 0644)

	// Create file with secret
	secretContent := `
package main

const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
`
	os.WriteFile(filepath.Join(tmpDir, "config.go"), []byte(secretContent), 0644)

	// Create vulnerable Dockerfile
	dockerfileContent := `FROM nginx:latest
RUN apt-get update
EXPOSE 22
ENV API_KEY=sk_test_12345
`
	os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfileContent), 0644)

	// Create vulnerable K8s manifest
	k8sContent := `
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
`
	os.WriteFile(filepath.Join(tmpDir, "pod.yaml"), []byte(k8sContent), 0644)

	// Create package.json with old lodash
	packageJSON := `{
  "name": "test-app",
  "dependencies": {
    "lodash": "4.17.20"
  }
}`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)

	// Configure all scanners
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{
				Enabled:          true,
				EntropyThreshold: 4.5,
			},
			IaC: config.IaCConfig{
				Enabled: true,
			},
			Dependencies: config.DependenciesConfig{
				Enabled: true,
			},
		},
		Policies: config.PoliciesConfig{
			Enabled: true,
		},
	}

	// Create engine and run scan
	engine := scanner.NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify scan results
	if result == nil {
		t.Fatal("Scan result is nil")
	}

	// Should have found multiple issues
	if len(result.Findings) == 0 {
		t.Fatal("Expected to find security issues")
	}

	t.Logf("Found %d findings across %d scanners", len(result.Findings), len(result.ScannerRuns))

	// Check for specific findings
	foundIssues := map[string]bool{
		"public-s3":         false,
		"aws-secret":        false,
		"privileged-pod":    false,
		"dockerfile-latest": false,
		"vulnerable-lodash": false,
	}

	for _, finding := range result.Findings {
		t.Logf("[%s] %s (%s) - %s", finding.Severity, finding.Title, finding.Scanner, finding.RuleID)

		switch {
		case finding.RuleID == "aws-s3-public-acl":
			foundIssues["public-s3"] = true
		case finding.RuleID == "aws-access-key" || finding.RuleID == "aws-secret-key":
			foundIssues["aws-secret"] = true
		case finding.RuleID == "k8s-privileged":
			foundIssues["privileged-pod"] = true
		case finding.RuleID == "latest-tag":
			foundIssues["dockerfile-latest"] = true
		case finding.Scanner == "dependencies" && strings.Contains(strings.ToLower(finding.Title), "lodash"):
			foundIssues["vulnerable-lodash"] = true
		}
	}

	// Verify critical findings
	if !foundIssues["public-s3"] {
		t.Error("Did not detect public S3 bucket")
	}

	if !foundIssues["aws-secret"] {
		t.Error("Did not detect AWS secrets")
	}

	// Verify severity distribution
	severityCounts := result.CountBySeverity()
	if severityCounts[api.SeverityCritical] == 0 {
		t.Error("Expected to find critical severity issues")
	}

	// Verify all scanners ran
	if len(result.ScannerRuns) == 0 {
		t.Error("No scanners were executed")
	}

	for _, run := range result.ScannerRuns {
		t.Logf("Scanner %s: %d findings in %d files (%s)",
			run.Scanner, run.FindingsCount, run.FilesCount, run.Duration.Std())

		if run.Error != "" {
			t.Errorf("Scanner %s failed: %s", run.Scanner, run.Error)
		}
	}

	// Check metadata
	if result.Metadata.TargetPath != tmpDir {
		t.Errorf("Expected target path %s, got %s", tmpDir, result.Metadata.TargetPath)
	}

	if result.Duration == 0 {
		t.Error("Scan duration is zero")
	}
}

// TestOutputFormats tests all report output formats
func TestOutputFormats(t *testing.T) {
	tmpDir := t.TempDir()

	// Create simple test file
	os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte(`
package main
const secret = "AKIAIOSFODNN7EXAMPLE"
`), 0644)

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := scanner.NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Test all formatters
	formats := []string{"text", "markdown", "json", "sarif", "html"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			reporter := reporter.New(cfg)
			output, err := reporter.Generate(result, format)

			if err != nil {
				t.Errorf("Failed to generate %s format: %v", format, err)
			}

			if len(output) == 0 {
				t.Errorf("%s format produced empty output", format)
			}

			t.Logf("%s format: %d bytes", format, len(output))
		})
	}
}

// TestFailOnSeverity verifies high-severity findings exist so fail-on gates can trip.
func TestFailOnSeverity(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "secrets.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
		FailOn: config.FailOnConfig{Severity: "high"},
	}

	engine := scanner.NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	counts := result.CountBySeverity()
	if counts[api.SeverityCritical]+counts[api.SeverityHigh] == 0 {
		t.Fatal("expected at least one critical/high finding for fail-on coverage")
	}
	if !api.MeetsMinimum(api.SeverityHigh, cfg.FailOn.Severity) {
		t.Fatal("expected high threshold to meet itself")
	}
	tripped := false
	for _, f := range result.Findings {
		if api.MeetsMinimum(f.Severity, cfg.FailOn.Severity) {
			tripped = true
			break
		}
	}
	if !tripped {
		t.Fatal("expected fail-on high to trip on findings")
	}
}

func TestConcurrentScanning(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple files
	for i := 0; i < 10; i++ {
		content := `package main
func main() {}
`
		filename := filepath.Join(tmpDir, fmt.Sprintf("file%d.go", i))
		os.WriteFile(filename, []byte(content), 0644)
	}

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
			IaC:     config.IaCConfig{Enabled: true},
		},
	}

	engine := scanner.NewEngine(cfg)

	// Run scan - should complete without race conditions
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Concurrent scan failed: %v", err)
	}

	// Multiple scanners should have run
	if len(result.ScannerRuns) < 2 {
		t.Error("Expected multiple scanners to run concurrently")
	}
}

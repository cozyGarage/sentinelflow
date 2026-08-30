package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestEngineInitialization(t *testing.T) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets:      config.SecretsConfig{Enabled: true},
			IaC:          config.IaCConfig{Enabled: true},
			Dependencies: config.DependenciesConfig{Enabled: true},
		},
		Policies: config.PoliciesConfig{
			Enabled: true,
		},
	}

	engine := NewEngine(cfg)

	if engine == nil {
		t.Fatal("Failed to create engine")
	}

	tmpDir := t.TempDir()
	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("scan empty dir: %v", err)
	}
	// Should have 4 scanners (secrets, iac, dependencies, policy)
	if len(result.ScannerRuns) != 4 {
		t.Errorf("Expected 4 scanner runs, got %d", len(result.ScannerRuns))
	}
}

func TestScanNonExistentPath(t *testing.T) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	_, err := engine.Scan(context.Background(), "/nonexistent/path")

	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	// Create temporary empty directory
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// Should have metadata
	if result.Metadata.TargetPath != tmpDir {
		t.Errorf("Expected target path %s, got %s", tmpDir, result.Metadata.TargetPath)
	}
}

func TestCollectFilesSkipsHidden(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files
	os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".hidden"), []byte("secret"), 0644)

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	os.Mkdir(gitDir, 0755)
	os.WriteFile(filepath.Join(gitDir, "config"), []byte("git config"), 0644)

	cfg := &config.Config{}
	engine := NewEngine(cfg)

	files, err := engine.collectFiles(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Failed to collect files: %v", err)
	}

	// Should include test.go and .hidden but not .git/config
	foundGitFile := false
	foundTestFile := false

	for _, f := range files {
		if filepath.Base(f) == "config" {
			foundGitFile = true
		}
		if filepath.Base(f) == "test.go" {
			foundTestFile = true
		}
	}

	if foundGitFile {
		t.Error("Should not collect files from .git directory")
	}

	if !foundTestFile {
		t.Error("Should collect test.go")
	}
}

func TestExcludeFiltering(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main_test.go"), []byte("package main"), 0644)

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Exclude: []string{"*_test.go"},
			Secrets: config.SecretsConfig{
				Enabled: true,
			},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check that excluded files were skipped
	for _, finding := range result.Findings {
		if filepath.Base(finding.Location.File) == "main_test.go" {
			t.Error("Should not scan files matching exclude pattern")
		}
	}
}

type stubScanner struct {
	name     string
	findings []api.Finding
	err      error
}

func (s *stubScanner) Name() string             { return s.name }
func (s *stubScanner) Supports(path string) bool { return true }
func (s *stubScanner) Scan(ctx context.Context, path string, opts interface{}) (*types.ScannerResult, error) {
	return &types.ScannerResult{Findings: s.findings, FilesCount: 1}, s.err
}

func TestEnginePreservesFindingsOnScannerError(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{}
	engine := NewEngine(cfg)
	engine.scanners = []Scanner{
		&stubScanner{
			name: "partial",
			findings: []api.Finding{
				{ID: "F1", Title: "kept", Severity: api.SeverityHigh, Scanner: "partial"},
			},
			err: fmt.Errorf("partial failure"),
		},
	}

	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "F1" {
		t.Fatalf("expected findings preserved on error, got %+v", result.Findings)
	}
	if len(result.ScannerRuns) != 1 || result.ScannerRuns[0].Error == "" {
		t.Fatalf("expected ScannerRun.Error set, got %+v", result.ScannerRuns)
	}
}

func TestSecretsAllowlistDoesNotHideIaCPaths(t *testing.T) {
	tmpDir := t.TempDir()
	tfDir := filepath.Join(tmpDir, "test", "infra")
	if err := os.MkdirAll(tfDir, 0755); err != nil {
		t.Fatal(err)
	}
	tf := `
resource "aws_s3_bucket" "public" {
  bucket = "example"
  acl    = "public-read"
}
`
	if err := os.WriteFile(filepath.Join(tfDir, "main.tf"), []byte(tf), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			// Secrets allowlist must NOT strip IaC from the shared walk.
			Exclude: nil,
			Secrets: config.SecretsConfig{
				Enabled:   false,
				Allowlist: []string{"test/**"},
			},
			IaC: config.IaCConfig{
				Enabled:    true,
				Severity:   "medium",
				Frameworks: []string{"terraform"},
			},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected IaC findings under test/** despite secrets allowlist")
	}
}

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestLoadFilePatternsFromScanRoot(t *testing.T) {
	tmpDir := t.TempDir()
	patternsDir := filepath.Join(tmpDir, ".sentinelflow")
	if err := os.MkdirAll(patternsDir, 0755); err != nil {
		t.Fatal(err)
	}

	patternsYAML := `patterns:
  - id: custom-api-token
    name: Custom API Token
    regex: "CUST_[A-Za-z0-9]{32}"
    severity: critical
    description: Custom API token pattern
`
	if err := os.WriteFile(filepath.Join(patternsDir, "patterns.yaml"), []byte(patternsYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	scanner := NewScanner(cfg)
	loaded, err := scanner.loadFilePatterns(tmpDir)
	if err != nil {
		t.Fatalf("loadFilePatterns: %v", err)
	}

	found := false
	for _, p := range loaded {
		if p.ID == "custom-api-token" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom pattern to be loaded from scan root")
	}
}

func TestCustomPatternDetectionViaScanRoot(t *testing.T) {
	tmpDir := t.TempDir()
	patternsDir := filepath.Join(tmpDir, ".sentinelflow")
	if err := os.MkdirAll(patternsDir, 0755); err != nil {
		t.Fatal(err)
	}

	patternsYAML := `patterns:
  - id: custom-token
    name: Custom Token
    regex: "CUST_[A-Za-z0-9]{20}"
    severity: high
    description: Custom token
`
	if err := os.WriteFile(filepath.Join(patternsDir, "patterns.yaml"), []byte(patternsYAML), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "app.env"), []byte("api_key=CUST_AbCdEfGhIjKlMnOpQrSt\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scanners.Secrets.Allowlist = nil
	cfg.Git.ScanHistory = false
	cfg.Scanners.Secrets.ScanGitHistory = false
	scanner := NewScanner(cfg)
	result, err := scanner.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "custom-token" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected custom pattern to detect token, got %+v", result.Findings)
	}
}

func TestSecretsHistoryDepthPrefersSecretsWhenGitHistoryOff(t *testing.T) {
	cfg := config.Default()
	cfg.Git.ScanHistory = false
	cfg.Git.HistoryDepth = 50
	cfg.Scanners.Secrets.ScanGitHistory = true
	cfg.Scanners.Secrets.MaxHistoryDepth = 7
	if got := secretsHistoryDepth(cfg); got != 7 {
		t.Fatalf("expected secrets max depth 7, got %d", got)
	}
}

func TestFindingIDsIncludePathToken(t *testing.T) {
	cfg := config.Default()
	cfg.Scanners.Secrets.Allowlist = nil
	s := NewScanner(cfg)
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "a.env"), []byte("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "b.env"), []byte("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD\n"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(context.Background(), tmp, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range result.Findings {
		if f.RuleID != "github-token" {
			continue
		}
		if ids[f.ID] {
			t.Fatalf("duplicate secret finding ID: %s", f.ID)
		}
		ids[f.ID] = true
	}
	if len(ids) < 2 {
		t.Fatalf("expected distinct IDs across files, got %d (%v)", len(ids), ids)
	}
}

func TestInvalidPatternsYAMLFailsScan(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, ".sentinelflow"), 0755); err != nil {
		t.Fatal(err)
	}
	bad := `patterns:
  - id: broken
    regex: "(unclosed"
`
	if err := os.WriteFile(filepath.Join(tmpDir, ".sentinelflow", "patterns.yaml"), []byte(bad), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(config.Default())
	_, err := s.Scan(context.Background(), tmpDir, nil)
	if err == nil {
		t.Fatal("expected invalid patterns.yaml to fail the scan")
	}
}

func TestSameLineSecretMatchesHaveDistinctIDs(t *testing.T) {
	tmp := t.TempDir()
	// Two AWS access keys on one line
	line := `keys = ["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"]` + "\n"
	if err := os.WriteFile(filepath.Join(tmp, "cfg.env"), []byte(line), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(config.Default())
	result, err := s.Scan(context.Background(), tmp, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	count := 0
	for _, f := range result.Findings {
		if f.RuleID != "aws-access-key" {
			continue
		}
		count++
		if ids[f.ID] {
			t.Fatalf("duplicate ID for same-line matches: %s", f.ID)
		}
		ids[f.ID] = true
	}
	if count < 2 {
		t.Fatalf("expected 2 aws-access-key findings on one line, got %d", count)
	}
}

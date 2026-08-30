package license

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestDetectDeniedLicense(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := `{
  "name": "test-app",
  "license": "GPL-3.0",
  "dependencies": {}
}`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644)

	s := NewScanner(&config.Config{
		Scanners: config.ScannersConfig{
			License: config.LicenseConfig{
				Enabled: true,
				Denied:  []string{"GPL-3.0"},
			},
		},
	})

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected denied license finding")
	}
}

func TestAllowedLicense(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := `{"name": "test-app", "license": "MIT"}`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644)

	s := NewScanner(&config.Config{
		Scanners: config.ScannersConfig{
			License: config.LicenseConfig{
				Denied: []string{"GPL-3.0"},
			},
		},
	})

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for MIT license, got %d", len(result.Findings))
	}
}

func TestInvalidPackageJSONSurfacesError(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("{not-json"), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(config.Default())
	_, err := s.Scan(context.Background(), tmpDir, nil)
	if err == nil {
		t.Fatal("expected parse error for invalid package.json")
	}
}

func TestMissingManifestsAreOK(t *testing.T) {
	tmpDir := t.TempDir()
	s := NewScanner(config.Default())
	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("empty dir should not error: %v", err)
	}
	if result.FilesCount != 0 {
		t.Fatalf("expected 0 files, got %d", result.FilesCount)
	}
}

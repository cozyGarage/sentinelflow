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

func TestLGPLDoesNotMatchDeniedGPL(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := `{"name": "test-app", "license": "LGPL-3.0"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

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
	if len(result.Findings) != 0 {
		t.Fatalf("LGPL-3.0 must not match denied GPL-3.0 via substring, got %d findings", len(result.Findings))
	}
}

func TestLicenseInListExactOnly(t *testing.T) {
	if licenseInList("LGPL-3.0", []string{"GPL-3.0"}) {
		t.Fatal("substring match must not apply")
	}
	if !licenseInList("GPL-3.0", []string{"gpl-3.0"}) {
		t.Fatal("exact case-insensitive match should apply")
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

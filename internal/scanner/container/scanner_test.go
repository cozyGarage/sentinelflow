package container

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestDetectImageWithPlatformAndMultiStage(t *testing.T) {
	tmpDir := t.TempDir()
	dockerfile := `FROM --platform=linux/amd64 golang:1.22 AS builder
WORKDIR /src
FROM --platform=linux/amd64 alpine:3.19
COPY --from=builder /src/app /app
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(&config.Config{})
	image := s.detectImage(tmpDir)
	if image != "alpine:3.19" {
		t.Fatalf("expected final stage alpine:3.19, got %q", image)
	}
}

func TestParseDockerfileFrom(t *testing.T) {
	if got := parseDockerfileFrom("FROM --platform=linux/arm64 nginx:1.25"); got != "nginx:1.25" {
		t.Fatalf("got %q", got)
	}
	if got := parseDockerfileFrom("FROM scratch"); got != "" {
		t.Fatalf("scratch should be ignored, got %q", got)
	}
}

func TestContainerFindingIDIncludesPackage(t *testing.T) {
	s := NewScanner(config.Default())
	report := []byte(`{
  "Results": [{
    "Vulnerabilities": [
      {"VulnerabilityID":"CVE-1","PkgName":"openssl","InstalledVersion":"1","Severity":"HIGH","Description":"a"},
      {"VulnerabilityID":"CVE-1","PkgName":"libssl","InstalledVersion":"1","Severity":"HIGH","Description":"b"}
    ]
  }]
}`)
	findings, err := s.parseTrivyOutput("img:tag", report)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ID == findings[1].ID {
		t.Fatalf("same CVE in different packages must have distinct IDs: %s", findings[0].ID)
	}
}

func TestValidateImageRef(t *testing.T) {
	if err := validateImageRef("-o /tmp/out"); err == nil {
		t.Fatal("expected option-like image refs to be rejected")
	}
	if err := validateImageRef("nginx:1.25"); err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

func TestParseSeverityViaAPI(t *testing.T) {
	if api.ParseSeverity("CRITICAL") != api.SeverityCritical {
		t.Fatal("expected CRITICAL -> critical")
	}
	if api.ParseSeverity("unknown") != api.SeverityInfo {
		t.Fatal("expected unknown -> info")
	}
}

func TestScanErrorsWithoutTrivy(t *testing.T) {
	if IsTrivyAvailable() {
		t.Skip("trivy is installed, skipping missing-trivy test")
	}

	s := NewScanner(&config.Config{
		Scanners: config.ScannersConfig{
			Container: config.ContainerConfig{Image: "alpine:latest"},
		},
	})
	result, err := s.Scan(context.Background(), ".", nil)
	if err == nil {
		t.Fatal("expected error when trivy is unavailable")
	}
	if result == nil {
		t.Fatal("expected non-nil result alongside error")
	}
}

func TestScanErrorsWithoutImage(t *testing.T) {
	s := NewScanner(&config.Config{
		Scanners: config.ScannersConfig{
			Container: config.ContainerConfig{Image: ""},
		},
	})
	result, err := s.Scan(context.Background(), t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected error when no image is configured")
	}
	if result == nil {
		t.Fatal("expected non-nil result alongside error")
	}
}

func TestSupportsDockerfile(t *testing.T) {
	s := NewScanner(&config.Config{})
	if !s.Supports("Dockerfile") {
		t.Error("should support Dockerfile")
	}
}

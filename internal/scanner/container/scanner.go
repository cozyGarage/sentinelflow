// Package container provides container image vulnerability scanning via Trivy
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner wraps Trivy for container scanning
type Scanner struct {
	config *config.Config
}

// ScannerResult is the shared scanner result type.
type ScannerResult = types.ScannerResult

// NewScanner creates a new container scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{config: cfg}
}

func (s *Scanner) Name() string { return "container" }

func (s *Scanner) Supports(path string) bool {
	base := filepath.Base(path)
	return base == "Dockerfile" || base == "docker-compose.yml" || base == "docker-compose.yaml"
}

// IsTrivyAvailable checks if trivy is installed
func IsTrivyAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

// Scan performs container vulnerability scanning
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{Findings: []api.Finding{}}

	image := s.config.Scanners.Container.Image
	if image == "" {
		image = s.detectImage(path)
	}

	if image == "" {
		return result, fmt.Errorf("container scan enabled but no image specified or detected")
	}

	if !IsTrivyAvailable() {
		return result, fmt.Errorf("trivy not installed; install from https://trivy.dev")
	}

	findings, err := s.runTrivy(ctx, image)
	result.Findings = findings
	result.FilesCount = 1
	if err != nil {
		return result, fmt.Errorf("trivy scan failed: %w", err)
	}
	return result, nil
}

func (s *Scanner) detectImage(path string) string {
	dockerfile := filepath.Join(path, "Dockerfile")
	data, err := os.ReadFile(dockerfile)
	if err != nil {
		return ""
	}

	var lastImage string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "FROM ") {
			continue
		}
		if img := parseDockerfileFrom(trimmed); img != "" {
			lastImage = img
		}
	}
	return lastImage
}

// parseDockerfileFrom extracts the image reference from a FROM instruction,
// skipping --platform/--chown-style flags and ignoring scratch.
func parseDockerfileFrom(fromLine string) string {
	fields := strings.Fields(fromLine)
	if len(fields) < 2 {
		return ""
	}
	// FROM [--platform=os/arch] image[:tag] [AS name]
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "--") {
			continue
		}
		if strings.EqualFold(f, "AS") {
			break
		}
		if strings.EqualFold(f, "scratch") {
			return ""
		}
		return f
	}
	return ""
}

func pkgToken(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("%08x", h.Sum32())
}

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string  `json:"VulnerabilityID"`
			PkgName          string  `json:"PkgName"`
			InstalledVersion string  `json:"InstalledVersion"`
			FixedVersion     string  `json:"FixedVersion"`
			Severity         string  `json:"Severity"`
			Title            string  `json:"Title"`
			Description      string  `json:"Description"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (s *Scanner) runTrivy(ctx context.Context, image string) ([]api.Finding, error) {
	if err := validateImageRef(image); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "trivy", "image", "--format", "json", "--quiet", "--", image)
	output, runErr := cmd.Output()

	var findings []api.Finding
	if len(output) > 0 {
		parsed, parseErr := s.parseTrivyOutput(image, output)
		if parseErr != nil && runErr == nil {
			return nil, parseErr
		}
		findings = parsed
		if parseErr != nil && runErr != nil {
			return findings, fmt.Errorf("%w (also failed to parse output: %v)", trivyRunError(runErr), parseErr)
		}
	} else if runErr == nil {
		return nil, fmt.Errorf("trivy returned empty output")
	}

	if runErr != nil {
		return findings, trivyRunError(runErr)
	}
	return findings, nil
}

func trivyRunError(err error) error {
	if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("%s: %s", err, string(exitErr.Stderr))
	}
	return err
}

func (s *Scanner) parseTrivyOutput(image string, output []byte) ([]api.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	var findings []api.Finding
	minSeverity := s.config.Scanners.Container.Severity

	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			sev := api.ParseSeverity(v.Severity)
			if !api.MeetsMinimum(sev, minSeverity) {
				continue
			}

			cvss := 0.0
			if nvd, ok := v.CVSS["nvd"]; ok {
				cvss = nvd.V3Score
			}

			remediation := ""
			if v.FixedVersion != "" {
				remediation = fmt.Sprintf("Update %s to version %s", v.PkgName, v.FixedVersion)
			}

			findings = append(findings, api.Finding{
				ID:          fmt.Sprintf("CONTAINER-%s-%s", v.VulnerabilityID, pkgToken(v.PkgName)),
				Type:        api.FindingTypeVulnerability,
				Severity:    sev,
				Title:       fmt.Sprintf("Container vulnerability: %s in %s", v.VulnerabilityID, v.PkgName),
				Description: v.Description,
				Location: api.Location{
					File:    image,
					Snippet: fmt.Sprintf("%s@%s", v.PkgName, v.InstalledVersion),
				},
				Remediation: remediation,
				Scanner:     "container",
				RuleID:      v.VulnerabilityID,
				CVE:         v.VulnerabilityID,
				CVSS:        cvss,
				Confidence:  0.95,
			})
		}
	}

	return findings, nil
}

func validateImageRef(image string) error {
	image = strings.TrimSpace(image)
	if image == "" {
		return fmt.Errorf("container image reference is empty")
	}
	if strings.HasPrefix(image, "-") {
		return fmt.Errorf("invalid container image reference %q: must not start with '-'", image)
	}
	if strings.ContainsAny(image, " \t\n\r") {
		return fmt.Errorf("invalid container image reference %q: contains whitespace", image)
	}
	return nil
}


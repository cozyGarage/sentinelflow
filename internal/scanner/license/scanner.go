// Package license provides license policy scanning
package license

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner checks dependency licenses against policy
type Scanner struct {
	config *config.Config
}

// ScannerResult contains scan results
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new license scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{config: cfg}
}

func (s *Scanner) Name() string { return "license" }

func (s *Scanner) Supports(path string) bool {
	base := filepath.Base(path)
	// Only manifests we actually inspect (no Cargo.toml — not implemented).
	return base == "package.json" || base == "go.mod"
}

// Scan performs license policy checking.
//
// Limits: transitive dependency licenses are resolved from a small hardcoded
// map (see knownLicenses), not a full license database or SBOM. Unknown
// packages are not flagged. Use an SBOM/license tool for comprehensive coverage.
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{Findings: []api.Finding{}}

	denied := s.config.Scanners.License.Denied
	if len(denied) == 0 {
		denied = []string{"GPL-3.0", "AGPL-3.0", "SSPL-1.0"}
	}
	allowed := s.config.Scanners.License.Allowed

	var errs []string
	if findings, err := s.checkPackageJSON(path, denied, allowed); err != nil {
		if !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("package.json: %v", err))
		}
	} else {
		result.Findings = append(result.Findings, findings...)
		result.FilesCount++
	}
	if findings, err := s.checkGoMod(path, denied, allowed); err != nil {
		if !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("go.mod: %v", err))
		}
	} else {
		result.Findings = append(result.Findings, findings...)
		result.FilesCount++
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("license scan errors: %s", strings.Join(errs, "; "))
	}
	return result, nil
}

func (s *Scanner) checkPackageJSON(path string, denied, allowed []string) ([]api.Finding, error) {
	pkgPath := filepath.Join(path, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Name         string            `json:"name"`
		License      string            `json:"license"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var findings []api.Finding
	if pkg.License != "" {
		if f := s.checkLicense(pkg.Name, pkg.License, denied, allowed, pkgPath); f != nil {
			findings = append(findings, *f)
		}
	}

	known := knownLicenses()
	for dep := range pkg.Dependencies {
		if lic, ok := known[dep]; ok {
			if f := s.checkLicense(dep, lic, denied, allowed, pkgPath); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

func (s *Scanner) checkGoMod(path string, denied, allowed []string) ([]api.Finding, error) {
	goModPath := filepath.Join(path, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	known := knownLicenses()
	var findings []api.Finding

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || !strings.Contains(trimmed, " ") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) >= 2 && !strings.HasPrefix(parts[0], "require") && parts[0] != ")" {
			mod := parts[0]
			if lic, ok := known[mod]; ok {
				if f := s.checkLicense(mod, lic, denied, allowed, goModPath); f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}

	return findings, nil
}

func (s *Scanner) checkLicense(name, license string, denied, allowed []string, filePath string) *api.Finding {
	if len(allowed) > 0 && !licenseInList(license, allowed) {
		return &api.Finding{
			ID:          fmt.Sprintf("LICENSE-%s", name),
			Type:        api.FindingTypePolicyViolation,
			Severity:    api.SeverityHigh,
			Title:       fmt.Sprintf("License not in allowlist: %s", license),
			Description: fmt.Sprintf("Package %s uses license %s which is not in scanners.license.allowed", name, license),
			Location:    api.Location{File: filePath, Snippet: fmt.Sprintf("%s (%s)", name, license)},
			Remediation: fmt.Sprintf("Replace %s with a package using an allowed license, or add %s to allowed", name, license),
			Scanner:     "license",
			RuleID:      "license-not-allowed",
			Confidence:  0.9,
			Metadata:    map[string]any{"license": license, "package": name},
		}
	}

	if licenseInList(license, denied) {
		return &api.Finding{
			ID:          fmt.Sprintf("LICENSE-%s", name),
			Type:        api.FindingTypePolicyViolation,
			Severity:    api.SeverityHigh,
			Title:       fmt.Sprintf("Denied license: %s", license),
			Description: fmt.Sprintf("Package %s uses license %s which is not allowed by policy", name, license),
			Location:    api.Location{File: filePath, Snippet: fmt.Sprintf("%s (%s)", name, license)},
			Remediation: fmt.Sprintf("Replace %s with an alternative using an approved license", name),
			Scanner:     "license",
			RuleID:      "denied-license",
			Confidence:  0.9,
			Metadata:    map[string]any{"license": license, "package": name},
		}
	}
	return nil
}

func licenseInList(license string, list []string) bool {
	for _, item := range list {
		// Exact match only — substring would make LGPL-3.0 match denied GPL-3.0.
		if strings.EqualFold(strings.TrimSpace(license), strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

// knownLicenses is a minimal hardcoded map for demo/CI noise reduction — not exhaustive.
func knownLicenses() map[string]string {
	return map[string]string{
		"readline":                       "GPL-3.0",
		"github.com/hashicorp/go-plugin": "MPL-2.0",
		"webpack":                        "MIT",
		"lodash":                         "MIT",
	}
}

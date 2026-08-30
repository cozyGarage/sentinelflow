// Package dependencies provides dependency vulnerability scanning
package dependencies

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner implements dependency vulnerability scanning
type Scanner struct {
	config     *config.Config
	ecosystems map[string]EcosystemScanner
	client     *vulndb.Client
}

// EcosystemScanner defines interface for package ecosystem scanners
type EcosystemScanner interface {
	Name() string
	Detect(path string) bool
	Scan(ctx context.Context, path string) ([]Dependency, error)
}

// Dependency represents a project dependency
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	FilePath  string
	Line      int
	Dev       bool
}

// Vulnerability represents a known vulnerability
type Vulnerability struct {
	ID          string
	CVE         string
	Severity    api.Severity
	CVSS        float64
	Description string
	FixedIn     string
	References  []string
}

// ScannerResult contains scan results (matching scanner.ScannerResult interface)
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new dependency scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{
		config:     cfg,
		ecosystems: make(map[string]EcosystemScanner),
	}

	client, err := vulndb.NewClient()
	if err == nil {
		s.client = client
	}

	s.ecosystems["go"] = &GoModScanner{}
	s.ecosystems["npm"] = &NpmScanner{}
	s.ecosystems["pip"] = &PipScanner{}
	s.ecosystems["maven"] = &MavenScanner{}
	s.ecosystems["cargo"] = &CargoScanner{}

	return s
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "dependencies"
}

// Supports returns true for dependency files
func (s *Scanner) Supports(path string) bool {
	base := filepath.Base(path)

	// Only files that implemented parsers actually read (no Gemfile/Ruby/Gradle yet).
	supportedFiles := []string{
		"go.mod",
		"package.json",
		"requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
		"pom.xml",
		"Cargo.toml", "Cargo.lock",
	}

	for _, f := range supportedFiles {
		if base == f {
			return true
		}
	}

	return false
}

// Scan performs dependency vulnerability scanning
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	ecosystemsFound := s.detectEcosystems(path)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var scanErrs []string

	for name, ecosys := range ecosystemsFound {
		wg.Add(1)
		go func(ecoName string, eco EcosystemScanner) {
			defer wg.Done()

			deps, err := eco.Scan(ctx, path)
			if err != nil {
				mu.Lock()
				scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", ecoName, err))
				mu.Unlock()
				return
			}

			for _, dep := range deps {
				if s.config.Scanners.Dependencies.IgnoreDev && dep.Dev {
					continue
				}

				vulns, err := s.checkVulnerabilities(ctx, dep)
				if err != nil {
					mu.Lock()
					scanErrs = append(scanErrs, fmt.Sprintf("%s/%s@%s: %v", dep.Ecosystem, dep.Name, dep.Version, err))
					mu.Unlock()
					continue
				}

				for _, vuln := range vulns {
					if s.shouldIgnoreVuln(vuln) {
						continue
					}
					if !api.MeetsMinimum(vuln.Severity, s.config.Scanners.Dependencies.Severity) {
						continue
					}

					finding := s.createFinding(dep, vuln, path)
					mu.Lock()
					result.Findings = append(result.Findings, finding)
					mu.Unlock()
				}
			}
		}(name, ecosys)
	}

	wg.Wait()

	result.FilesCount = len(ecosystemsFound)
	if len(scanErrs) > 0 {
		return result, fmt.Errorf("dependency scan errors: %s", strings.Join(scanErrs, "; "))
	}
	return result, nil
}

func (s *Scanner) shouldIgnoreVuln(vuln Vulnerability) bool {
	for _, ignored := range s.config.Scanners.Dependencies.IgnoreCVEs {
		if strings.EqualFold(ignored, vuln.CVE) || strings.EqualFold(ignored, vuln.ID) {
			return true
		}
	}
	return false
}

// detectEcosystems detects which package ecosystems are used
func (s *Scanner) detectEcosystems(path string) map[string]EcosystemScanner {
	detected := make(map[string]EcosystemScanner)

	cfgEcosystems := s.config.Scanners.Dependencies.Ecosystems
	autoDetect := len(cfgEcosystems) == 0 || (len(cfgEcosystems) == 1 && cfgEcosystems[0] == "auto")

	for name, ecosys := range s.ecosystems {
		if !autoDetect {
			enabled := false
			for _, e := range cfgEcosystems {
				if e == name || e == "auto" {
					enabled = true
					break
				}
			}
			if !enabled {
				continue
			}
		}

		if ecosys.Detect(path) {
			detected[name] = ecosys
		}
	}

	return detected
}

func (s *Scanner) checkVulnerabilities(ctx context.Context, dep Dependency) ([]Vulnerability, error) {
	if s.client == nil {
		return nil, fmt.Errorf("vulnerability database unavailable")
	}

	version := normalizeVersion(dep.Version)
	vulns, err := s.client.Query(ctx, dep.Ecosystem, dep.Name, version)
	if err != nil {
		return nil, err
	}

	var results []Vulnerability
	for _, v := range vulns {
		results = append(results, Vulnerability{
			ID:          v.ID,
			CVE:         v.CVE,
			Severity:    severityFromVulnDB(v.Severity, v.CVSS),
			CVSS:        v.CVSS,
			Description: firstNonEmpty(v.Summary, v.Details),
			FixedIn:     firstFixedVersion(v.Fixed, v.Affected),
			References:  v.References,
		})
	}

	return results, nil
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	return version
}

func severityFromVulnDB(severity string, cvss float64) api.Severity {
	trimmed := strings.TrimSpace(severity)
	if trimmed != "" {
		sev := api.ParseSeverity(trimmed)
		switch strings.ToLower(trimmed) {
		case "critical", "high", "medium", "moderate", "low", "info", "informational":
			return sev
		}
	}

	if cvss >= 9.0 {
		return api.SeverityCritical
	}
	if cvss >= 7.0 {
		return api.SeverityHigh
	}
	if cvss >= 4.0 {
		return api.SeverityMedium
	}
	if cvss > 0 {
		return api.SeverityLow
	}

	return api.SeverityMedium
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstFixedVersion(fixed []string, affected []vulndb.Range) string {
	if len(fixed) > 0 {
		return fixed[0]
	}
	for _, r := range affected {
		if r.Fixed != "" {
			return r.Fixed
		}
	}
	return ""
}

// createFinding creates a finding from a vulnerability
func (s *Scanner) createFinding(dep Dependency, vuln Vulnerability, basePath string) api.Finding {
	relPath, _ := filepath.Rel(basePath, dep.FilePath)

	return api.Finding{
		ID:          fmt.Sprintf("DEP-%s-%s", dep.Ecosystem, vuln.ID),
		Type:        api.FindingTypeVulnerability,
		Severity:    vuln.Severity,
		Title:       fmt.Sprintf("Vulnerable dependency: %s", dep.Name),
		Description: fmt.Sprintf("%s@%s: %s", dep.Name, dep.Version, vuln.Description),
		Location: api.Location{
			File:      relPath,
			StartLine: dep.Line,
			EndLine:   dep.Line,
			Snippet:   fmt.Sprintf("%s@%s", dep.Name, dep.Version),
		},
		Remediation: fmt.Sprintf("Update %s to a patched version%s", dep.Name, formatFixedIn(vuln.FixedIn)),
		References:  vuln.References,
		Scanner:     "dependencies",
		RuleID:      vuln.ID,
		CVE:         vuln.CVE,
		CVSS:        vuln.CVSS,
		Confidence:  0.95,
	}
}

func formatFixedIn(fixed string) string {
	if fixed == "" {
		return ""
	}
	return " (fixed in " + fixed + ")"
}

// GoModScanner scans Go modules
type GoModScanner struct{}

func (g *GoModScanner) Name() string { return "go" }

func (g *GoModScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil
}

func (g *GoModScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	goModPath := filepath.Join(path, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	lines := strings.Split(string(content), "\n")

	inRequire := false
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if strings.HasPrefix(trimmed, "require") {
			parts := strings.Fields(trimmed)
			// Single-line: require module version [// indirect]
			if len(parts) >= 3 && parts[0] == "require" && parts[1] != "(" {
				deps = append(deps, Dependency{
					Name:      parts[1],
					Version:   parts[2],
					Ecosystem: "go",
					FilePath:  goModPath,
					Line:      lineNum + 1,
				})
				continue
			}
			// Multi-line: require (
			inRequire = true
			continue
		}

		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}

		if inRequire {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: "go",
					FilePath:  goModPath,
					Line:      lineNum + 1,
				})
			}
		}
	}

	return deps, nil
}

// NpmScanner scans npm packages
type NpmScanner struct{}

func (n *NpmScanner) Name() string { return "npm" }

func (n *NpmScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "package.json"))
	return err == nil
}

func (n *NpmScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	pkgPath := filepath.Join(path, "package.json")
	content, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency

	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   normalizeVersion(version),
			Ecosystem: "npm",
			FilePath:  pkgPath,
		})
	}

	for name, version := range pkg.DevDependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   normalizeVersion(version),
			Ecosystem: "npm",
			FilePath:  pkgPath,
			Dev:       true,
		})
	}

	return deps, nil
}


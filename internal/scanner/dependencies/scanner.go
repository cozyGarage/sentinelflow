// Package dependencies provides dependency vulnerability scanning
package dependencies

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"golang.org/x/mod/modfile"
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
	// Inventory identifies the source used to select this package version.
	// It is descriptive evidence, not proof of the contents of a built artifact.
	Inventory string
	// InstallPath distinguishes multiple installed instances of the same package.
	InstallPath string
}

// Vulnerability represents a known vulnerability
type Vulnerability struct {
	ID          string
	Source      string
	Aliases     []string
	CVE         string
	Severity    api.Severity
	CVSS        float64
	Description string
	FixedIn     string
	References  []string
}

// ScannerResult is the shared scanner result type.
type ScannerResult = types.ScannerResult

// NewScanner creates a new dependency scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{
		config:     cfg,
		ecosystems: make(map[string]EcosystemScanner),
	}

	var offlineMaxAge []time.Duration
	if cfg.Scanners.Dependencies.OfflineRequireFresh {
		if age, err := cfg.OfflineMaxAgeDuration(); err == nil {
			offlineMaxAge = append(offlineMaxAge, age)
		}
	}
	useOffline := cfg.Scanners.Dependencies.Offline || cfg.Scanners.Dependencies.OfflineRequireFresh
	client, err := vulndb.NewClient(vulndb.OfflineOptions(useOffline, offlineMaxAge...)...)
	if err != nil {
		s.client = nil
	} else {
		s.client = client
	}

	s.ecosystems["go"] = &GoModScanner{
		ResolveGraph: cfg.Scanners.Dependencies.GoModuleGraph,
		AllowNetwork: cfg.Scanners.Dependencies.GoModuleGraphAllowNetwork && !cfg.Scanners.Dependencies.Offline && !cfg.Scanners.Dependencies.OfflineRequireFresh,
	}
	s.ecosystems["npm"] = &NpmScanner{}
	s.ecosystems["pip"] = &PipScanner{}
	s.ecosystems["maven"] = &MavenScanner{}
	s.ecosystems["cargo"] = &CargoScanner{}
	s.ecosystems["rubygems"] = &RubyGemsScanner{}
	s.ecosystems["gradle"] = &GradleScanner{}
	s.ecosystems["composer"] = &ComposerScanner{}
	s.ecosystems["nuget"] = &NuGetScanner{}

	return s
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "dependencies"
}

// Supports returns true for dependency files
func (s *Scanner) Supports(path string) bool {
	base := filepath.Base(path)

	// Only files that implemented parsers actually read (bare Gemfile unsupported).
	supportedFiles := []string{
		"go.mod",
		"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
		"pom.xml",
		"Cargo.toml", "Cargo.lock",
		"Gemfile.lock",
		"gradle.lockfile", "composer.lock", "packages.lock.json",
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

	files, err := types.ResolveFiles(path, opts, rootFiles)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var scanErrs []string
	var deps []Dependency
	var scanWarnings []string

	for _, dir := range s.manifestDirs(files) {
		for name, ecosys := range s.detectEcosystems(dir) {
			result.FilesCount++
			wg.Add(1)
			go func(ecoName, dir string, eco EcosystemScanner) {
				defer wg.Done()
				found, err := eco.Scan(ctx, dir)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					rel, _ := filepath.Rel(path, dir)
					scanErrs = append(scanErrs, fmt.Sprintf("%s (%s): %v", ecoName, filepath.ToSlash(rel), err))
					return
				}
				if ecoName == "go" {
					rel, _ := filepath.Rel(path, dir)
					message := "Go inventory is read from go.mod requirements; go.sum, workspace selection, and replacements are not used to establish a resolved package graph"
					if goScanner, ok := eco.(*GoModScanner); ok && goScanner.ResolveGraph {
						message = "Go inventory is resolved with `go list -m all` for this module with workspace mode disabled; this is module metadata, not proof of build, platform, or artifact contents"
					}
					scanWarnings = append(scanWarnings, fmt.Sprintf("%s: %s", filepath.ToSlash(filepath.Join(rel, "go.mod")), message))
				}
				for _, dep := range found {
					if s.config.Scanners.Dependencies.IgnoreDev && dep.Dev {
						continue
					}
					deps = append(deps, dep)
				}
			}(name, dir, ecosys)
		}
	}
	wg.Wait()
	sort.Strings(scanWarnings)
	result.Warnings = scanWarnings

	// Stable order keeps findings and error messages deterministic.
	sort.Slice(deps, func(i, j int) bool {
		a, b := deps[i], deps[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.InstallPath < b.InstallPath
	})
	sort.Strings(scanErrs)

	all, err := s.checkAll(ctx, deps)
	if err != nil {
		scanErrs = append(scanErrs, err.Error())
	}
	for i, vulns := range all {
		for _, vuln := range vulns {
			if s.shouldIgnoreVuln(vuln) {
				continue
			}
			if !api.MeetsMinimum(vuln.Severity, s.config.Scanners.Dependencies.Severity) {
				continue
			}
			result.Findings = append(result.Findings, s.createFinding(deps[i], vuln, path))
		}
	}

	if len(scanErrs) > 0 {
		if s.client != nil {
			result.VulnerabilityData = s.client.VulnerabilityData()
		}
		return result, fmt.Errorf("dependency scan errors: %s", strings.Join(scanErrs, "; "))
	}
	if s.client != nil {
		result.VulnerabilityData = s.client.VulnerabilityData()
	}
	return result, nil
}

// rootFiles is the fallback when no engine file list is provided: only the scan root is searched.
func rootFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files, nil
}

// manifestDirs returns each directory that holds a supported manifest, sorted.
func (s *Scanner) manifestDirs(files []string) []string {
	seen := map[string]bool{}
	var dirs []string
	for _, f := range files {
		if !s.Supports(f) {
			continue
		}
		d := filepath.Dir(f)
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	return dirs
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
	all, err := s.checkAll(ctx, []Dependency{dep})
	if err != nil {
		if len(all) > 0 {
			return all[0], err
		}
		return nil, err
	}
	return all[0], nil
}

// checkAll looks up every dependency in one batched query; results align with deps.
func (s *Scanner) checkAll(ctx context.Context, deps []Dependency) ([][]Vulnerability, error) {
	if len(deps) == 0 {
		return nil, nil
	}
	if s.client == nil {
		return nil, fmt.Errorf("vulnerability database unavailable")
	}

	qs := make([]vulndb.PackageQuery, len(deps))
	for i, dep := range deps {
		qs[i] = vulndb.PackageQuery{Ecosystem: dep.Ecosystem, Name: dep.Name, Version: normalizeVersion(dep.Version)}
	}
	found, err := s.client.QueryMany(ctx, qs)

	out := make([][]Vulnerability, len(deps))
	for i, vulns := range found {
		for _, v := range vulns {
			out[i] = append(out[i], Vulnerability{
				ID:          v.ID,
				Source:      v.Source,
				Aliases:     append([]string(nil), v.Aliases...),
				CVE:         v.CVE,
				Severity:    severityFromVulnDB(v.Severity, v.CVSS),
				CVSS:        v.CVSS,
				Description: cmp.Or(v.Summary, v.Details),
				FixedIn:     firstFixedVersion(v.Fixed, v.Affected),
				References:  v.References,
			})
		}
	}
	return out, err
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
	metadata := map[string]any{"package": dep.Name, "version": dep.Version, "ecosystem": dep.Ecosystem}
	if vuln.Source != "" {
		metadata["vulnerability_source"] = vuln.Source
	}
	if len(vuln.Aliases) > 0 {
		metadata["vulnerability_aliases"] = append([]string(nil), vuln.Aliases...)
	}
	if dep.Inventory != "" {
		metadata["inventory"] = dep.Inventory
	}
	if dep.InstallPath != "" {
		metadata["install_path"] = dep.InstallPath
	}

	return api.Finding{
		ID:          fmt.Sprintf("DEP-%s-%s-%s", dep.Ecosystem, fingerprint.Token(dep.Name+"@"+dep.Version+"@"+dep.InstallPath), vuln.ID),
		Type:        api.FindingTypeVulnerability,
		Severity:    vuln.Severity,
		Title:       fmt.Sprintf("Vulnerable dependency: %s", dep.Name),
		Description: fmt.Sprintf("%s@%s: %s", dep.Name, dep.Version, vuln.Description),
		Location: api.Location{
			File:      relPath,
			StartLine: dep.Line,
			EndLine:   dep.Line,
			Snippet:   fmt.Sprintf("%s@%s (%s)", dep.Name, dep.Version, dep.InstallPath),
		},
		Remediation: fmt.Sprintf("Update %s to a patched version%s", dep.Name, formatFixedIn(vuln.FixedIn)),
		Metadata:    metadata,
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

// GoModScanner scans declared Go requirements or an explicitly selected module graph.
type GoModScanner struct {
	ResolveGraph bool
	AllowNetwork bool
	goCommand    string
}

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

	parsed, err := modfile.Parse(goModPath, content, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}
	if g.ResolveGraph && len(parsed.Replace) > 0 {
		return nil, fmt.Errorf("resolve Go module graph: replacements in go.mod are not yet supported; use declared requirements until SC-016/SC-017 support is enabled")
	}
	deps := make([]Dependency, 0, len(parsed.Require))
	for _, req := range parsed.Require {
		line := 0
		if req.Syntax != nil {
			line = req.Syntax.Start.Line
		}
		deps = append(deps, Dependency{
			Name: req.Mod.Path, Version: req.Mod.Version, Ecosystem: "go",
			FilePath: goModPath, Line: line, Dev: req.Indirect,
			Inventory: "go.mod_require",
		})
	}
	if g.ResolveGraph {
		return g.resolveGraph(ctx, goModPath, deps)
	}
	return deps, nil
}

func parseGoSum(path string) ([]Dependency, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var deps []Dependency
	seen := map[string]bool{}
	for lineNum, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, version := fields[0], fields[1]
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "go",
			FilePath:  path,
			Line:      lineNum + 1,
		})
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
	if deps, err := n.scanLockfile(path); err == nil && len(deps) > 0 {
		return deps, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

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

// scanLockfile prefers package-lock.json / npm-shrinkwrap.json / yarn.lock exact versions.
func (n *NpmScanner) scanLockfile(path string) ([]Dependency, error) {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		lockPath := filepath.Join(path, name)
		content, err := os.ReadFile(lockPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		deps, err := parseNpmLock(content, lockPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(deps) > 0 {
			return deps, nil
		}
	}

	for _, lf := range []struct {
		name  string
		parse func([]byte, string) ([]Dependency, error)
	}{{"yarn.lock", parseYarnLock}, {"pnpm-lock.yaml", parsePnpmLock}} {
		lockPath := filepath.Join(path, lf.name)
		content, err := os.ReadFile(lockPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		deps, err := lf.parse(content, lockPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", lf.name, err)
		}
		if len(deps) > 0 {
			return deps, nil
		}
	}
	return nil, os.ErrNotExist
}

// parseYarnLock parses classic Yarn v1 lockfiles (not Berry).
func parseYarnLock(content []byte, lockPath string) ([]Dependency, error) {
	var deps []Dependency
	seen := map[string]bool{}
	lines := strings.Split(string(content), "\n")

	var headers []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Entry header: "pkg@range:" or multiple comma-separated keys ending with :
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			header := strings.TrimSuffix(trimmed, ":")
			headers = strings.Split(header, ",")
			for j := range headers {
				headers[j] = strings.Trim(strings.TrimSpace(headers[j]), `"`)
			}
			continue
		}
		if len(headers) == 0 {
			continue
		}
		if strings.HasPrefix(trimmed, "version ") {
			ver := strings.TrimSpace(strings.TrimPrefix(trimmed, "version "))
			ver = strings.Trim(ver, `"`)
			for _, h := range headers {
				name := yarnPackageName(h)
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				deps = append(deps, Dependency{
					Name:      name,
					Version:   ver,
					Ecosystem: "npm",
					FilePath:  lockPath,
				})
			}
			headers = nil
		}
	}
	return deps, nil
}

func yarnPackageName(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	// @scope/name@version or name@version (version may be range)
	if strings.HasPrefix(key, "@") {
		// @scope/pkg@^1.0.0
		rest := key[1:]
		if i := strings.LastIndex(rest, "@"); i > 0 {
			return "@" + rest[:i]
		}
		return key
	}
	if i := strings.LastIndex(key, "@"); i > 0 {
		return key[:i]
	}
	return key
}

func parseNpmLock(content []byte, lockPath string) ([]Dependency, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		Dependencies map[string]*npmLockDependency `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}

	var deps []Dependency

	// lockfileVersion 2/3
	packagePaths := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		packagePaths = append(packagePaths, key)
	}
	sort.Strings(packagePaths)
	for _, key := range packagePaths {
		pkg := lock.Packages[key]
		if key == "" || pkg.Version == "" {
			continue
		}
		name := npmPackageName(key)
		if name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:        name,
			Version:     pkg.Version,
			Ecosystem:   "npm",
			FilePath:    lockPath,
			Dev:         pkg.Dev,
			Inventory:   "package-lock",
			InstallPath: key,
		})
	}

	// lockfileVersion 1
	if len(deps) == 0 {
		rootPaths := make([]string, 0, len(lock.Dependencies))
		for name := range lock.Dependencies {
			rootPaths = append(rootPaths, name)
		}
		sort.Strings(rootPaths)
		for _, name := range rootPaths {
			pkg := lock.Dependencies[name]
			if err := collectNpmV1(lockPath, name, pkg, "", 0, &deps); err != nil {
				return nil, err
			}
		}
	}
	return deps, nil
}

const maxNpmLockDepth = 256

func npmPackageName(installPath string) string {
	parts := strings.Split(strings.Trim(installPath, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "node_modules" && i+1 < len(parts) {
			if strings.HasPrefix(parts[i+1], "@") && i+2 < len(parts) {
				return parts[i+1] + "/" + parts[i+2]
			}
			return parts[i+1]
		}
	}
	return ""
}

type npmLockDependency struct {
	Version      string                        `json:"version"`
	Dev          bool                          `json:"dev"`
	Dependencies map[string]*npmLockDependency `json:"dependencies"`
}

func collectNpmV1(lockPath, name string, pkg *npmLockDependency, parent string, depth int, out *[]Dependency) error {
	if depth > maxNpmLockDepth {
		return fmt.Errorf("package-lock.json dependency nesting exceeds %d", maxNpmLockDepth)
	}
	installPath := filepath.ToSlash(filepath.Join(parent, "node_modules", name))
	if pkg != nil && pkg.Version != "" {
		*out = append(*out, Dependency{Name: name, Version: pkg.Version, Ecosystem: "npm", FilePath: lockPath, Dev: pkg.Dev, Inventory: "package-lock", InstallPath: installPath})
	}
	if pkg == nil {
		return nil
	}
	children := make([]string, 0, len(pkg.Dependencies))
	for child := range pkg.Dependencies {
		children = append(children, child)
	}
	sort.Strings(children)
	for _, child := range children {
		if err := collectNpmV1(lockPath, child, pkg.Dependencies[child], installPath, depth+1, out); err != nil {
			return err
		}
	}
	return nil
}

// Collect parses every supported manifest/lockfile in dir without querying a
// vulnerability database. Used by SBOM generation so both share one set of parsers.
func Collect(ctx context.Context, dir string) ([]Dependency, error) {
	s := NewScanner(config.Default())
	found := s.detectEcosystems(dir)
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)

	var deps []Dependency
	var errs []string
	for _, name := range names {
		got, err := found[name].Scan(ctx, dir)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		deps = append(deps, got...)
	}
	if len(errs) > 0 {
		return deps, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return deps, nil
}

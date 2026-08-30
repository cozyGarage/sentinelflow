package dependencies

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// PipScanner scans Python packages from requirements, pyproject, and lockfiles.
type PipScanner struct{}

func (p *PipScanner) Name() string { return "pip" }

func (p *PipScanner) Detect(path string) bool {
	// Bare Pipfile is not parsed (only Pipfile.lock) — detecting it alone was a false green.
	files := []string{
		"requirements.txt",
		"Pipfile.lock",
		"pyproject.toml",
		"poetry.lock",
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			return true
		}
	}
	return false
}

func (p *PipScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	var deps []Dependency
	var errs []string

	parsers := []func(string) ([]Dependency, error){
		p.scanRequirements,
		p.scanPoetryLock,
		p.scanPipfileLock,
		p.scanPyProject,
	}
	for _, parse := range parsers {
		found, err := parse(path)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, err.Error())
			}
			continue
		}
		deps = append(deps, found...)
	}

	if len(deps) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("python dependency scan failed: %s", strings.Join(errs, "; "))
	}
	return dedupeDependencies(deps), nil
}

func (p *PipScanner) scanRequirements(path string) ([]Dependency, error) {
	reqPath := filepath.Join(path, "requirements.txt")
	content, err := os.ReadFile(reqPath)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	for i, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		name, version, ok := parsePythonRequirement(trimmed)
		if !ok || version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "pip",
			FilePath:  reqPath,
			Line:      i + 1,
		})
	}
	return deps, nil
}

var pythonReqPattern = regexp.MustCompile(`(?i)^([A-Za-z0-9][A-Za-z0-9_.+\-]*)\s*(?:\[.*?\])?\s*(?:===|==|>=|<=|~=|!=|>|<)\s*([^;,\s]+)`)

func parsePythonRequirement(spec string) (name, version string, ok bool) {
	spec = strings.TrimSpace(spec)
	if at := strings.Index(spec, " @ "); at > 0 {
		return "", "", false
	}
	m := pythonReqPattern.FindStringSubmatch(spec)
	if len(m) < 3 {
		return "", "", false
	}
	return m[1], normalizeVersion(m[2]), true
}

func (p *PipScanner) scanPyProject(path string) ([]Dependency, error) {
	file := filepath.Join(path, "pyproject.toml")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var doc map[string]interface{}
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("pyproject.toml: %w", err)
	}

	var deps []Dependency

	if project, ok := doc["project"].(map[string]interface{}); ok {
		deps = append(deps, parsePythonDepList(asStringSlice(project["dependencies"]), file, false)...)
		if optional, ok := project["optional-dependencies"].(map[string]interface{}); ok {
			for _, group := range optional {
				deps = append(deps, parsePythonDepList(asStringSlice(group), file, true)...)
			}
		}
	}

	if tool, ok := doc["tool"].(map[string]interface{}); ok {
		if poetry, ok := tool["poetry"].(map[string]interface{}); ok {
			if poetryDeps, ok := poetry["dependencies"].(map[string]interface{}); ok {
				deps = append(deps, parsePoetryTable(poetryDeps, file, false)...)
			}
			if dev, ok := poetry["dev-dependencies"].(map[string]interface{}); ok {
				deps = append(deps, parsePoetryTable(dev, file, true)...)
			}
			if groups, ok := poetry["group"].(map[string]interface{}); ok {
				for _, groupVal := range groups {
					group, _ := groupVal.(map[string]interface{})
					groupDeps, _ := group["dependencies"].(map[string]interface{})
					deps = append(deps, parsePoetryTable(groupDeps, file, true)...)
				}
			}
		}
	}

	return deps, nil
}

func parsePythonDepList(specs []string, file string, dev bool) []Dependency {
	var deps []Dependency
	for _, spec := range specs {
		name, version, ok := parsePythonRequirement(spec)
		if !ok || version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "pip",
			FilePath:  file,
			Dev:       dev,
		})
	}
	return deps
}

func parsePoetryTable(table map[string]interface{}, file string, dev bool) []Dependency {
	var deps []Dependency
	for name, raw := range table {
		if strings.EqualFold(name, "python") {
			continue
		}
		version := poetryVersion(raw)
		if version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   normalizeVersion(version),
			Ecosystem: "pip",
			FilePath:  file,
			Dev:       dev,
		})
	}
	return deps
}

func poetryVersion(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return strings.Trim(v, "^~>=<!= ")
	case map[string]interface{}:
		if ver, ok := v["version"].(string); ok {
			return strings.Trim(ver, "^~>=<!= ")
		}
	}
	return ""
}

func (p *PipScanner) scanPoetryLock(path string) ([]Dependency, error) {
	file := filepath.Join(path, "poetry.lock")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Package []struct {
			Name     string `toml:"name"`
			Version  string `toml:"version"`
			Category string `toml:"category"`
			Optional bool   `toml:"optional"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("poetry.lock: %w", err)
	}

	var deps []Dependency
	for _, pkg := range doc.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "pip",
			FilePath:  file,
			Dev:       pkg.Category == "dev" || pkg.Optional,
		})
	}
	return deps, nil
}

func (p *PipScanner) scanPipfileLock(path string) ([]Dependency, error) {
	file := filepath.Join(path, "Pipfile.lock")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("Pipfile.lock: %w", err)
	}

	var deps []Dependency
	for name, meta := range doc.Default {
		version := strings.TrimPrefix(meta.Version, "==")
		if version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "pip",
			FilePath:  file,
		})
	}
	for name, meta := range doc.Develop {
		version := strings.TrimPrefix(meta.Version, "==")
		if version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "pip",
			FilePath:  file,
			Dev:       true,
		})
	}
	return deps, nil
}

// MavenScanner scans Maven pom.xml dependencies.
type MavenScanner struct{}

func (m *MavenScanner) Name() string { return "maven" }

func (m *MavenScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "pom.xml"))
	return err == nil
}

type mavenPOM struct {
	XMLName              xml.Name          `xml:"project"`
	GroupID              string            `xml:"groupId"`
	ArtifactID           string            `xml:"artifactId"`
	Version              string            `xml:"version"`
	Properties           mavenProperties   `xml:"properties"`
	Dependencies         []mavenDependency `xml:"dependencies>dependency"`
	DependencyManagement []mavenDependency `xml:"dependencyManagement>dependencies>dependency"`
}

type mavenProperties struct {
	Raw []byte `xml:",innerxml"`
}

type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

func (m *MavenScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	pomPath := filepath.Join(path, "pom.xml")
	content, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, err
	}

	var pom mavenPOM
	if err := xml.Unmarshal(content, &pom); err != nil {
		return nil, fmt.Errorf("pom.xml: %w", err)
	}

	props := parseMavenProperties(pom.Properties.Raw, pom)
	var deps []Dependency

	add := func(dep mavenDependency, managed bool) {
		group := resolveMavenValue(dep.GroupID, props)
		artifact := resolveMavenValue(dep.ArtifactID, props)
		version := resolveMavenValue(dep.Version, props)
		if group == "" || artifact == "" || version == "" {
			return
		}
		if strings.Contains(version, "${") {
			return
		}
		dev := dep.Scope == "test" || dep.Scope == "provided" || strings.EqualFold(dep.Optional, "true")
		deps = append(deps, Dependency{
			Name:      group + ":" + artifact,
			Version:   normalizeVersion(version),
			Ecosystem: "maven",
			FilePath:  pomPath,
			Dev:       dev || managed && dep.Scope == "test",
		})
	}

	for _, dep := range pom.Dependencies {
		add(dep, false)
	}
	// Only include dependencyManagement entries when they have an explicit version
	// and are not already present from <dependencies>.
	seen := make(map[string]bool)
	for _, d := range deps {
		seen[d.Name] = true
	}
	for _, dep := range pom.DependencyManagement {
		group := resolveMavenValue(dep.GroupID, props)
		artifact := resolveMavenValue(dep.ArtifactID, props)
		key := group + ":" + artifact
		if seen[key] {
			continue
		}
		add(dep, true)
	}

	return dedupeDependencies(deps), nil
}

func parseMavenProperties(raw []byte, pom mavenPOM) map[string]string {
	props := map[string]string{
		"project.groupId":    pom.GroupID,
		"project.artifactId": pom.ArtifactID,
		"project.version":    pom.Version,
		"groupId":            pom.GroupID,
		"artifactId":         pom.ArtifactID,
		"version":            pom.Version,
	}
	if len(raw) == 0 {
		return props
	}
	dec := xml.NewDecoder(strings.NewReader("<properties>" + string(raw) + "</properties>"))
	var current string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "properties" {
				current = t.Name.Local
			}
		case xml.CharData:
			if current != "" {
				props[current] = strings.TrimSpace(string(t))
			}
		case xml.EndElement:
			current = ""
		}
	}
	return props
}

var mavenPropPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

func resolveMavenValue(value string, props map[string]string) string {
	if value == "" {
		return ""
	}
	return mavenPropPattern.ReplaceAllStringFunc(value, func(match string) string {
		key := match[2 : len(match)-1]
		if v, ok := props[key]; ok {
			return v
		}
		return match
	})
}

// CargoScanner scans Rust packages from Cargo.lock (preferred) or Cargo.toml.
type CargoScanner struct{}

func (c *CargoScanner) Name() string { return "cargo" }

func (c *CargoScanner) Detect(path string) bool {
	if _, err := os.Stat(filepath.Join(path, "Cargo.toml")); err == nil {
		return true
	}
	_, err := os.Stat(filepath.Join(path, "Cargo.lock"))
	return err == nil
}

func (c *CargoScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	if deps, err := c.scanLock(path); err == nil && len(deps) > 0 {
		return deps, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return c.scanToml(path)
}

func (c *CargoScanner) scanLock(path string) ([]Dependency, error) {
	file := filepath.Join(path, "Cargo.lock")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
			Source  string `toml:"source"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("Cargo.lock: %w", err)
	}

	var deps []Dependency
	for _, pkg := range doc.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		// Skip path/workspace members without a registry source when possible.
		if pkg.Source == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "cargo",
			FilePath:  file,
		})
	}
	return dedupeDependencies(deps), nil
}

func (c *CargoScanner) scanToml(path string) ([]Dependency, error) {
	file := filepath.Join(path, "Cargo.toml")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Dependencies    map[string]interface{} `toml:"dependencies"`
		DevDependencies map[string]interface{} `toml:"dev-dependencies"`
		BuildDependencies map[string]interface{} `toml:"build-dependencies"`
	}
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("Cargo.toml: %w", err)
	}

	var deps []Dependency
	deps = append(deps, parseCargoTable(doc.Dependencies, file, false)...)
	deps = append(deps, parseCargoTable(doc.DevDependencies, file, true)...)
	deps = append(deps, parseCargoTable(doc.BuildDependencies, file, true)...)
	return dedupeDependencies(deps), nil
}

func parseCargoTable(table map[string]interface{}, file string, dev bool) []Dependency {
	var deps []Dependency
	for name, raw := range table {
		version := cargoVersion(raw)
		if version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   normalizeVersion(version),
			Ecosystem: "cargo",
			FilePath:  file,
			Dev:       dev,
		})
	}
	return deps
}

func cargoVersion(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return strings.Trim(v, "^~>=<!= ")
	case map[string]interface{}:
		if ver, ok := v["version"].(string); ok {
			return strings.Trim(ver, "^~>=<!= ")
		}
	}
	return ""
}

func asStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func dedupeDependencies(deps []Dependency) []Dependency {
	seen := make(map[string]int, len(deps))
	var out []Dependency
	for _, dep := range deps {
		key := dep.Ecosystem + "|" + dep.Name + "|" + dep.Version + "|" + dep.FilePath
		if idx, ok := seen[key]; ok {
			// Prefer non-dev annotation when duplicates exist.
			if out[idx].Dev && !dep.Dev {
				out[idx].Dev = false
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, dep)
	}
	return out
}

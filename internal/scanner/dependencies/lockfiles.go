package dependencies

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// parsePnpmLock reads pnpm-lock.yaml v5 (/name/1.0.0), v6 (/name@1.0.0) and v9 (name@1.0.0).
func parsePnpmLock(content []byte, lockPath string) ([]Dependency, error) {
	var lock struct {
		Packages map[string]struct {
			Dev bool `yaml:"dev"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(content, &lock); err != nil {
		return nil, err
	}
	var deps []Dependency
	for key, pkg := range lock.Packages {
		name, version := pnpmKey(key)
		if name == "" || version == "" {
			continue
		}
		deps = append(deps, Dependency{Name: name, Version: version, Ecosystem: "npm", FilePath: lockPath, Dev: pkg.Dev})
	}
	return dedupeDependencies(deps), nil
}

func pnpmKey(key string) (name, version string) {
	key = strings.TrimPrefix(key, "/")
	key, _, _ = strings.Cut(key, "(") // peer suffix: react-dom@18.0.0(react@18.0.0)
	if i := strings.LastIndex(key, "@"); i > 0 {
		return key[:i], key[i+1:]
	}
	if i := strings.LastIndex(key, "/"); i > 0 { // v5
		return key[:i], key[i+1:]
	}
	return "", ""
}

// GradleScanner reads gradle.lockfile (Gradle dependency locking).
type GradleScanner struct{}

func (g *GradleScanner) Name() string { return "gradle" }

func (g *GradleScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "gradle.lockfile"))
	return err == nil
}

func (g *GradleScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	file := filepath.Join(path, "gradle.lockfile")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var deps []Dependency
	for i, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		// group:artifact:version=configuration,configuration
		coord, confs, _ := strings.Cut(line, "=")
		parts := strings.Split(coord, ":")
		if len(parts) != 3 {
			continue
		}
		deps = append(deps, Dependency{
			Name:      parts[0] + ":" + parts[1],
			Version:   parts[2],
			Ecosystem: "maven",
			FilePath:  file,
			Line:      i + 1,
			Dev:       testOnly(confs),
		})
	}
	return dedupeDependencies(deps), nil
}

// testOnly is true when every Gradle configuration is a test one.
func testOnly(confs string) bool {
	if confs == "" {
		return false
	}
	for _, c := range strings.Split(confs, ",") {
		if !strings.HasPrefix(strings.TrimSpace(c), "test") {
			return false
		}
	}
	return true
}

// ComposerScanner reads composer.lock (PHP).
type ComposerScanner struct{}

func (c *ComposerScanner) Name() string { return "composer" }

func (c *ComposerScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "composer.lock"))
	return err == nil
}

func (c *ComposerScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	file := filepath.Join(path, "composer.lock")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var lock struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("composer.lock: %w", err)
	}
	var deps []Dependency
	for dev, list := range map[bool][]pkg{false: lock.Packages, true: lock.PackagesDev} {
		for _, p := range list {
			if p.Name == "" || p.Version == "" || strings.HasPrefix(p.Version, "dev-") {
				continue
			}
			deps = append(deps, Dependency{Name: p.Name, Version: p.Version, Ecosystem: "composer", FilePath: file, Dev: dev})
		}
	}
	return dedupeDependencies(deps), nil
}

// NuGetScanner reads packages.lock.json (.NET).
type NuGetScanner struct{}

func (n *NuGetScanner) Name() string { return "nuget" }

func (n *NuGetScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "packages.lock.json"))
	return err == nil
}

func (n *NuGetScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	file := filepath.Join(path, "packages.lock.json")
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("packages.lock.json: %w", err)
	}
	var deps []Dependency
	for _, framework := range lock.Dependencies {
		for name, d := range framework {
			if d.Resolved == "" || d.Type == "Project" {
				continue
			}
			deps = append(deps, Dependency{Name: name, Version: d.Resolved, Ecosystem: "nuget", FilePath: file})
		}
	}
	return dedupeDependencies(deps), nil
}

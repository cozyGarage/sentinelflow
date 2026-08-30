// Package sbom provides Software Bill of Materials generation
package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cozygarage/sentinelflow/internal/config"
)

// Scanner generates SBOM documents from project lockfiles
type Scanner struct{}

// ScannerResult contains SBOM generation results
type ScannerResult struct {
	Document   *CycloneDX
	FilesCount int
}

// CycloneDX represents a CycloneDX 1.5 BOM document
type CycloneDX struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata contains BOM metadata
type Metadata struct {
	Timestamp string `json:"timestamp"`
	Component Component `json:"component"`
}

// Component represents a software component
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// NewScanner creates a new SBOM scanner
func NewScanner(_ *config.Config) *Scanner {
	return &Scanner{}
}

// Generate creates a CycloneDX SBOM from the target path.
// Missing lockfiles are skipped; corrupt lockfiles fail the generation.
func (s *Scanner) Generate(ctx context.Context, path string) (*ScannerResult, error) {
	result := &ScannerResult{
		Document: &CycloneDX{
			BOMFormat:    "CycloneDX",
			SpecVersion:  "1.5",
			SerialNumber: fmt.Sprintf("urn:uuid:sentinelflow-%d", time.Now().UnixNano()),
			Version:      1,
			Metadata: Metadata{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Component: Component{
					Type: "application",
					Name: filepath.Base(path),
				},
			},
			Components: []Component{},
		},
	}

	var components []Component
	var errs []string

	parsers := []struct {
		name string
		fn   func(string) ([]Component, error)
	}{
		{"go.mod", s.parseGoMod},
		{"package-lock.json", s.parsePackageLock},
		{"Cargo.lock", s.parseCargoLock},
	}
	for _, p := range parsers {
		comps, err := p.fn(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: %v", p.name, err))
			continue
		}
		components = append(components, comps...)
		result.FilesCount++
	}

	result.Document.Components = components
	if len(errs) > 0 {
		return result, fmt.Errorf("SBOM parse errors: %s", strings.Join(errs, "; "))
	}
	return result, nil
}

// WriteJSON writes the SBOM to a file
func (s *Scanner) WriteJSON(doc *CycloneDX, outputPath string) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}

func (s *Scanner) parseGoMod(path string) ([]Component, error) {
	goModPath := filepath.Join(path, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	var components []Component
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "require") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 && parts[0] == "require" && parts[1] != "(" {
				components = append(components, Component{
					Type:    "library",
					Name:    parts[1],
					Version: parts[2],
					PURL:    fmt.Sprintf("pkg:golang/%s@%s", parts[1], parts[2]),
				})
				continue
			}
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
				components = append(components, Component{
					Type:    "library",
					Name:    parts[0],
					Version: parts[1],
					PURL:    fmt.Sprintf("pkg:golang/%s@%s", parts[0], parts[1]),
				})
			}
		}
	}
	return components, nil
}

func (s *Scanner) parsePackageLock(path string) ([]Component, error) {
	lockPath := filepath.Join(path, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var components []Component
	for name, pkg := range lock.Packages {
		if name == "" || pkg.Version == "" {
			continue
		}
		cleanName := strings.TrimPrefix(name, "node_modules/")
		components = append(components, Component{
			Type:    "library",
			Name:    cleanName,
			Version: pkg.Version,
			PURL:    fmt.Sprintf("pkg:npm/%s@%s", cleanName, pkg.Version),
		})
	}
	return components, nil
}

func (s *Scanner) parseCargoLock(path string) ([]Component, error) {
	lockPath := filepath.Join(path, "Cargo.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	var components []Component
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "name = ") {
			name := strings.Trim(strings.TrimPrefix(trimmed, "name = "), `"`)
			components = append(components, Component{
				Type: "library",
				Name: name,
				PURL: fmt.Sprintf("pkg:cargo/%s", name),
			})
		}
	}
	return components, nil
}

// Package sbom provides Software Bill of Materials generation
package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/dependencies"
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
	Timestamp string    `json:"timestamp"`
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

	deps, err := dependencies.Collect(ctx, path)
	seen := map[string]bool{}
	ecosystems := map[string]bool{}
	for _, d := range deps {
		purl := PURL(d.Ecosystem, d.Name, d.Version)
		if seen[purl] {
			continue
		}
		seen[purl] = true
		ecosystems[d.Ecosystem] = true
		result.Document.Components = append(result.Document.Components, Component{
			Type: "library", Name: d.Name, Version: d.Version, PURL: purl,
		})
	}
	sort.Slice(result.Document.Components, func(i, j int) bool {
		return result.Document.Components[i].PURL < result.Document.Components[j].PURL
	})
	result.FilesCount = len(ecosystems)
	if err != nil {
		return result, fmt.Errorf("SBOM parse errors: %w", err)
	}
	return result, nil
}

// PURL builds a package URL (https://github.com/package-url/purl-spec) for a dependency.
func PURL(ecosystem, name, version string) string {
	typ := map[string]string{
		"go": "golang", "npm": "npm", "pip": "pypi", "maven": "maven",
		"cargo": "cargo", "rubygems": "gem", "composer": "composer", "nuget": "nuget",
	}[ecosystem]
	if typ == "" {
		typ = ecosystem
	}
	switch typ {
	case "maven":
		name = strings.Replace(name, ":", "/", 1) // group:artifact -> group/artifact
	case "npm":
		name = strings.Replace(name, "@", "%40", 1) // @scope/name
	}
	v := strings.TrimPrefix(version, "v")
	if typ == "golang" {
		v = version // Go module versions keep their v prefix
	}
	return fmt.Sprintf("pkg:%s/%s@%s", typ, name, v)
}

// WriteJSON writes the SBOM to a file
func (s *Scanner) WriteJSON(doc *CycloneDX, outputPath string) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}

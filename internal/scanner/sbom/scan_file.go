package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// ScanFile queries OSV for components listed in a CycloneDX JSON SBOM.
func (s *Scanner) ScanFile(ctx context.Context, path string) (*api.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc CycloneDX
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}
	client, err := vulndb.NewClient()
	if err != nil {
		return nil, err
	}
	result := &api.ScanResult{
		Findings: []api.Finding{},
		Metadata: api.ScanMetadata{TargetPath: path},
		ScannerRuns: []api.ScannerRun{{
			Scanner: "sbom", FilesCount: 1,
		}},
	}
	for _, c := range doc.Components {
		eco, name := purlEcosystem(c.PURL, c.Name)
		if c.Version == "" {
			continue
		}
		vulns, err := client.Query(ctx, eco, name, strings.TrimPrefix(c.Version, "v"))
		if err != nil {
			continue
		}
		for _, v := range vulns {
			f := api.Finding{
				ID:          fmt.Sprintf("SBOM-%s-%s", v.ID, fingerprint.ValueHash(c.Name)),
				Type:        api.FindingTypeVulnerability,
				Severity:    api.ParseSeverity(v.Severity),
				Title:       fmt.Sprintf("%s in %s@%s", v.ID, c.Name, c.Version),
				Description: firstNonEmpty(v.Summary, v.Details),
				Location:    api.Location{File: path, Snippet: c.PURL},
				Scanner:     "sbom",
				RuleID:      v.ID,
				CVE:         v.CVE,
				CVSS:        v.CVSS,
				References:  v.References,
				Confidence:  0.9,
			}
			if len(v.Fixed) > 0 {
				f.Remediation = "Update to " + v.Fixed[0]
			}
			f.Fingerprint = fingerprint.Of(f)
			result.Findings = append(result.Findings, f)
		}
	}
	result.ScannerRuns[0].FindingsCount = len(result.Findings)
	return result, nil
}

func purlEcosystem(purl, name string) (eco, pkg string) {
	pkg = name
	switch {
	case strings.HasPrefix(purl, "pkg:golang/"):
		return "go", strings.TrimPrefix(strings.Split(purl, "@")[0], "pkg:golang/")
	case strings.HasPrefix(purl, "pkg:npm/"):
		return "npm", strings.TrimPrefix(strings.Split(purl, "@")[0], "pkg:npm/")
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return "pip", strings.TrimPrefix(strings.Split(purl, "@")[0], "pkg:pypi/")
	case strings.HasPrefix(purl, "pkg:cargo/"):
		return "cargo", strings.TrimPrefix(strings.Split(purl, "@")[0], "pkg:cargo/")
	case strings.HasPrefix(purl, "pkg:maven/"):
		return "maven", strings.TrimPrefix(strings.Split(purl, "@")[0], "pkg:maven/")
	case strings.HasPrefix(purl, "pkg:gem/"):
		return "rubygems", strings.TrimPrefix(strings.Split(purl, "@")[0], "pkg:gem/")
	default:
		return "npm", pkg
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// WriteSPDX writes a minimal SPDX 2.3 JSON document from a CycloneDX BOM.
func (s *Scanner) WriteSPDX(doc *CycloneDX, outputPath string) error {
	type spdxPkg struct {
		SPDXID      string `json:"SPDXID"`
		Name        string `json:"name"`
		VersionInfo string `json:"versionInfo,omitempty"`
	}
	out := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              doc.Metadata.Component.Name,
		"documentNamespace": doc.SerialNumber,
		"packages":          []spdxPkg{},
	}
	var pkgs []spdxPkg
	for i, c := range doc.Components {
		pkgs = append(pkgs, spdxPkg{
			SPDXID: fmt.Sprintf("SPDXRef-Package-%d", i+1), Name: c.Name, VersionInfo: c.Version,
		})
	}
	out["packages"] = pkgs
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

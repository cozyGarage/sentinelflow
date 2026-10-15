package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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
	client, err := vulndb.NewClient(vulndb.OfflineOptions(s.offline)...)
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
	var errs []string
	for _, c := range doc.Components {
		eco, name := purlEcosystem(c.PURL)
		if c.Version == "" || eco == "" {
			continue
		}
		vulns, err := client.Query(ctx, eco, name, strings.TrimPrefix(c.Version, "v"))
		if err != nil {
			// Record it: a dropped lookup must not turn into a silent pass.
			errs = append(errs, fmt.Sprintf("%s: %v", c.PURL, err))
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
	if len(errs) > 0 {
		result.ScannerRuns[0].Error = fmt.Sprintf("%d component lookups failed: %s", len(errs), strings.Join(errs, "; "))
	}
	return result, nil
}

// purlEcosystem maps a package URL to our ecosystem name and OSV package name.
// Unsupported or malformed purls return an empty ecosystem.
func purlEcosystem(purl string) (eco, pkg string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", ""
	}
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok {
		return "", ""
	}
	if i := strings.LastIndex(path, "@"); i > 0 { // > 0: a leading @ is an npm scope
		path = path[:i]
	}
	name, err := url.PathUnescape(path)
	if err != nil || name == "" {
		return "", ""
	}
	switch typ {
	case "golang":
		return "go", name
	case "npm", "cargo", "composer", "nuget":
		return typ, name
	case "pypi":
		return "pip", name
	case "gem":
		return "rubygems", name
	case "maven":
		return "maven", strings.Replace(name, "/", ":", 1) // OSV uses group:artifact
	}
	return "", ""
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

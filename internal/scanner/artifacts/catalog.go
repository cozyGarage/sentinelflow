package artifacts

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Component is a software component extracted from an artifact.
type Component struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
	Path      string
}

func componentsFromBuildInfo(bi *buildinfo.BuildInfo, path string) []Component {
	var out []Component
	if bi.GoVersion != "" {
		out = append(out, Component{
			Name:      "stdlib",
			Version:   strings.TrimPrefix(bi.GoVersion, "go"),
			Ecosystem: "go",
			PURL:      fmt.Sprintf("pkg:golang/stdlib@%s", strings.TrimPrefix(bi.GoVersion, "go")),
			Path:      path,
		})
	}
	for _, m := range bi.Deps {
		if m == nil || m.Path == "" {
			continue
		}
		ver := m.Version
		if m.Replace != nil && m.Replace.Version != "" {
			ver = m.Replace.Version
		}
		out = append(out, Component{
			Name:      m.Path,
			Version:   ver,
			Ecosystem: "go",
			PURL:      fmt.Sprintf("pkg:golang/%s@%s", m.Path, ver),
			Path:      path,
		})
	}
	return out
}

func componentsFromPomProperties(data []byte, path string) []Component {
	group, artifact, version := "", "", ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "groupId="):
			group = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			artifact = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			version = strings.TrimPrefix(line, "version=")
		}
	}
	if artifact == "" || version == "" {
		return nil
	}
	name := artifact
	if group != "" {
		name = group + ":" + artifact
	}
	return []Component{{
		Name: name, Version: version, Ecosystem: "maven",
		PURL: fmt.Sprintf("pkg:maven/%s/%s@%s", group, artifact, version),
		Path: path,
	}}
}

func componentsFromWheelMetadata(data []byte, path string) []Component {
	name, version := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "name:") {
			name = strings.TrimSpace(line[5:])
		}
		if strings.HasPrefix(lower, "version:") {
			version = strings.TrimSpace(line[8:])
		}
	}
	if name == "" || version == "" {
		return nil
	}
	return []Component{{
		Name: name, Version: version, Ecosystem: "pip",
		PURL: fmt.Sprintf("pkg:pypi/%s@%s", name, version),
		Path: path,
	}}
}

func componentsFromPackageJSON(data []byte, path string) []Component {
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Name == "" {
		return nil
	}
	return []Component{{
		Name: doc.Name, Version: doc.Version, Ecosystem: "npm",
		PURL: fmt.Sprintf("pkg:npm/%s@%s", doc.Name, doc.Version),
		Path: path,
	}}
}

func componentsFromDpkgStatus(data []byte, path string) []Component {
	var out []Component
	var pkg, ver string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if pkg != "" && ver != "" {
				out = append(out, Component{Name: pkg, Version: ver, Ecosystem: "debian", Path: path,
					PURL: fmt.Sprintf("pkg:deb/debian/%s@%s", pkg, ver)})
			}
			pkg, ver = "", ""
			continue
		}
		if strings.HasPrefix(line, "Package: ") {
			pkg = strings.TrimPrefix(line, "Package: ")
		}
		if strings.HasPrefix(line, "Version: ") {
			ver = strings.TrimPrefix(line, "Version: ")
		}
	}
	if pkg != "" && ver != "" {
		out = append(out, Component{Name: pkg, Version: ver, Ecosystem: "debian", Path: path,
			PURL: fmt.Sprintf("pkg:deb/debian/%s@%s", pkg, ver)})
	}
	return out
}

func componentsFromApkInstalled(data []byte, path string) []Component {
	var out []Component
	var pkg, ver string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			if pkg != "" && ver != "" {
				out = append(out, Component{Name: pkg, Version: ver, Ecosystem: "alpine", Path: path,
					PURL: fmt.Sprintf("pkg:apk/alpine/%s@%s", pkg, ver)})
			}
			pkg, ver = "", ""
			continue
		}
		if strings.HasPrefix(line, "P:") {
			pkg = strings.TrimPrefix(line, "P:")
		}
		if strings.HasPrefix(line, "V:") {
			ver = strings.TrimPrefix(line, "V:")
		}
	}
	return out
}

func (s *Scanner) componentFindings(ctx context.Context, c Component) []api.Finding {
	if c.Name == "" {
		return nil
	}
	file, artifact := splitArtifact(c.Path)
	base := api.Finding{
		ID:          fmt.Sprintf("ART-COMP-%s-%s", c.Ecosystem, fingerprint.ValueHash(c.Name+"@"+c.Version)),
		Type:        api.FindingTypeComponent,
		Severity:    api.SeverityInfo,
		Title:       fmt.Sprintf("Component %s@%s", c.Name, c.Version),
		Description: fmt.Sprintf("Discovered %s package %s version %s", c.Ecosystem, c.Name, c.Version),
		Location: api.Location{
			File:         file,
			ArtifactPath: artifact,
			Snippet:      c.PURL,
		},
		Scanner:     "artifacts",
		RuleID:      "artifact-component",
		Confidence:  0.9,
		ValueHash:   fingerprint.ValueHash(c.Name + "@" + c.Version),
		Fingerprint: "",
	}
	if s.client == nil || c.Version == "" {
		return nil // catalog-only when OSV unavailable; vulns come from matcher
	}
	vulns, err := s.client.Query(ctx, osvEcosystem(c.Ecosystem), c.Name, strings.TrimPrefix(c.Version, "v"))
	if err != nil || len(vulns) == 0 {
		return nil
	}
	var out []api.Finding
	for _, v := range vulns {
		f := base
		f.ID = fmt.Sprintf("ART-VULN-%s-%s", v.ID, fingerprint.ValueHash(c.Name))
		f.Type = api.FindingTypeVulnerability
		f.Severity = api.ParseSeverity(v.Severity)
		f.Title = fmt.Sprintf("Vulnerable component: %s@%s (%s)", c.Name, c.Version, v.ID)
		f.Description = firstNonEmpty(v.Summary, v.Details)
		f.CVE = v.CVE
		f.CVSS = v.CVSS
		f.RuleID = v.ID
		f.References = v.References
		if len(v.Fixed) > 0 {
			f.Remediation = "Update to " + v.Fixed[0]
		} else if len(v.Affected) > 0 && v.Affected[0].Fixed != "" {
			f.Remediation = "Update to " + v.Affected[0].Fixed
		}
		f.Fingerprint = fingerprint.Of(f)
		out = append(out, f)
	}
	return out
}

func osvEcosystem(eco string) string {
	switch eco {
	case "go":
		return "go"
	case "npm":
		return "npm"
	case "pip":
		return "pip"
	case "maven":
		return "maven"
	default:
		return eco
	}
}

func splitArtifact(path string) (file, artifact string) {
	if i := strings.Index(path, "!/"); i >= 0 {
		return path[:i], path
	}
	return path, ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

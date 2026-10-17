// Package vex applies OpenVEX statements to vulnerability findings.
// https://github.com/openvex/spec
package vex

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

type document struct {
	Statements []statement `json:"statements"`
}

type statement struct {
	Vulnerability struct {
		ID      string   `json:"@id"`
		Name    string   `json:"name"`
		Aliases []string `json:"aliases"`
	} `json:"vulnerability"`
	Products []struct {
		ID          string            `json:"@id"`
		Identifiers map[string]string `json:"identifiers"`
	} `json:"products"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// Rule is one suppressing statement: a vulnerability, optionally scoped to packages.
type Rule struct {
	Vulns    []string
	Products []Product
	Status   string
	Reason   string
	Broad    bool
}

// Product is a package parsed from a purl.
type Product struct {
	Ecosystem string
	Name      string
	Version   string
}

// LoadOptions controls compatibility-sensitive VEX matching behavior.
type LoadOptions struct {
	// AllowBroad authorizes product-free or versionless suppression statements.
	AllowBroad bool
}

// Load reads OpenVEX documents and keeps not_affected and fixed statements.
func Load(paths []string) ([]Rule, error) {
	return LoadWithOptions(paths, LoadOptions{})
}

// LoadWithOptions reads OpenVEX documents using explicit scope policy.
func LoadWithOptions(paths []string, options LoadOptions) ([]Rule, error) {
	var rules []Rule
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var doc document
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, st := range doc.Statements {
			if st.Status != "not_affected" && st.Status != "fixed" {
				continue
			}
			r := Rule{Status: st.Status, Reason: st.Justification}
			if len(st.Products) == 0 {
				if !options.AllowBroad {
					return nil, fmt.Errorf("%s: %s statement has no product; set vex_allow_broad: true only if global suppression is intended", p, st.Status)
				}
				r.Broad = true
			}
			for _, v := range append([]string{st.Vulnerability.Name}, st.Vulnerability.Aliases...) {
				if v != "" {
					r.Vulns = append(r.Vulns, v)
				}
			}
			for _, prod := range st.Products {
				purl := prod.Identifiers["purl"]
				if strings.HasPrefix(prod.ID, "pkg:") {
					if purl != "" && purl != prod.ID {
						return nil, fmt.Errorf("%s: conflicting VEX product PURL identifiers %q and %q", p, prod.ID, purl)
					}
					purl = prod.ID
				}
				pr, ok := parsePURL(purl)
				if !ok {
					return nil, fmt.Errorf("%s: unsupported or invalid VEX product PURL %q", p, purl)
				}
				if pr.Version == "" && !options.AllowBroad {
					return nil, fmt.Errorf("%s: versionless VEX product %q requires vex_allow_broad: true", p, purl)
				}
				r.Products = append(r.Products, pr)
			}
			if len(r.Vulns) > 0 {
				rules = append(rules, r)
			}
		}
	}
	return rules, nil
}

// parsePURL extracts namespace/name and version from pkg:type/namespace/name@version.
func parsePURL(raw string) (Product, bool) {
	// Until findings carry these attributes, do not parse and discard them:
	// qualifier and subpath can change package identity.
	if strings.ContainsAny(raw, "?#") || strings.Contains(strings.ToLower(raw), "%2f") {
		return Product{}, false
	}
	rest, ok := strings.CutPrefix(raw, "pkg:")
	if !ok {
		return Product{}, false
	}
	typeName, path, ok := strings.Cut(rest, "/")
	if !ok {
		return Product{}, false
	}
	ecosystem, ok := purlEcosystems[strings.ToLower(typeName)]
	if !ok || path == "" {
		return Product{}, false
	}
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	namePart, version, hasVersion := strings.Cut(last, "@")
	parts[len(parts)-1] = namePart
	decoded := make([]string, len(parts))
	for i, part := range parts {
		var err error
		decoded[i], err = url.PathUnescape(part)
		if err != nil || decoded[i] == "" || decoded[i] == "." || decoded[i] == ".." {
			return Product{}, false
		}
	}
	switch ecosystem {
	case "go":
		if len(decoded) < 2 {
			return Product{}, false
		}
	case "maven", "composer":
		if len(decoded) != 2 {
			return Product{}, false
		}
	case "npm":
		if len(decoded) > 2 || len(decoded) == 1 && strings.HasPrefix(decoded[0], "@") || len(decoded) == 2 && !strings.HasPrefix(decoded[0], "@") {
			return Product{}, false
		}
	case "pip", "cargo", "nuget", "rubygems":
		if len(decoded) != 1 {
			return Product{}, false
		}
	}
	name := strings.Join(decoded, "/")
	if ecosystem == "maven" && len(decoded) > 1 {
		name = strings.Join(decoded[:len(decoded)-1], ".") + ":" + decoded[len(decoded)-1]
	}
	name = canonicalPackageName(ecosystem, name)
	if name == "" {
		return Product{}, false
	}
	if hasVersion {
		var err error
		version, err = url.PathUnescape(version)
		if err != nil || version == "" {
			return Product{}, false
		}
	}
	return Product{Ecosystem: ecosystem, Name: name, Version: version}, true
}

var purlEcosystems = map[string]string{
	"golang": "go", "npm": "npm", "maven": "maven", "pypi": "pip",
	"cargo": "cargo", "nuget": "nuget", "gem": "rubygems", "composer": "composer",
}

// Filter drops findings covered by a rule. Product-scoped rules only match
// findings whose metadata names the package (dependency and component findings).
func Filter(findings []api.Finding, rules []Rule) (kept, suppressed []api.Finding) {
	if len(rules) == 0 {
		return findings, nil
	}
	for _, f := range findings {
		if matchesAny(f, rules) {
			suppressed = append(suppressed, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

func matchesAny(f api.Finding, rules []Rule) bool {
	for _, r := range rules {
		if !matchesVuln(f, r.Vulns) {
			continue
		}
		if r.Broad {
			return true
		}
		pkg, _ := f.Metadata["package"].(string)
		ver, _ := f.Metadata["version"].(string)
		ecosystem, _ := f.Metadata["ecosystem"].(string)
		for _, p := range r.Products {
			if strings.EqualFold(p.Ecosystem, ecosystem) && canonicalPackageName(p.Ecosystem, p.Name) == canonicalPackageName(p.Ecosystem, pkg) && (p.Version == "" || p.Version == ver) {
				return true
			}
		}
	}
	return false
}

func canonicalPackageName(ecosystem, name string) string {
	switch strings.ToLower(ecosystem) {
	case "pip":
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case "nuget", "composer":
		return strings.ToLower(name)
	default:
		return name
	}
}

func matchesVuln(f api.Finding, vulns []string) bool {
	aliases := metadataAliases(f.Metadata["vulnerability_aliases"])
	for _, v := range vulns {
		if v != "" && (strings.EqualFold(v, f.CVE) || strings.EqualFold(v, f.RuleID) || containsAlias(aliases, v)) {
			return true
		}
	}
	return false
}

func metadataAliases(value any) []string {
	switch aliases := value.(type) {
	case []string:
		return aliases
	case []any:
		out := make([]string, 0, len(aliases))
		for _, alias := range aliases {
			if s, ok := alias.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func containsAlias(aliases []string, id string) bool {
	for _, alias := range aliases {
		if strings.EqualFold(alias, id) {
			return true
		}
	}
	return false
}

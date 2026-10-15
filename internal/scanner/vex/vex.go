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
		ID string `json:"@id"`
	} `json:"products"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// Rule is one suppressing statement: a vulnerability, optionally scoped to packages.
type Rule struct {
	Vulns    []string
	Products []Product // empty: applies to every package
	Status   string
	Reason   string
}

// Product is a package parsed from a purl.
type Product struct {
	Name    string
	Version string // empty: any version
}

// Load reads OpenVEX documents and keeps not_affected and fixed statements.
func Load(paths []string) ([]Rule, error) {
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
			for _, v := range append([]string{st.Vulnerability.Name, st.Vulnerability.ID}, st.Vulnerability.Aliases...) {
				if v != "" {
					r.Vulns = append(r.Vulns, v)
				}
			}
			for _, prod := range st.Products {
				if pr, ok := parsePURL(prod.ID); ok {
					r.Products = append(r.Products, pr)
				}
			}
			// A statement that names products but none parse as purls must not become global.
			if len(st.Products) > 0 && len(r.Products) == 0 {
				continue
			}
			if len(r.Vulns) > 0 {
				rules = append(rules, r)
			}
		}
	}
	return rules, nil
}

// parsePURL extracts namespace/name and version from pkg:type/namespace/name@version.
func parsePURL(purl string) (Product, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return Product{}, false
	}
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	_, path, ok := strings.Cut(rest, "/")
	if !ok {
		return Product{}, false
	}
	path, version, _ := strings.Cut(path, "@")
	name, err := url.PathUnescape(path)
	if err != nil {
		return Product{}, false
	}
	version, _ = url.PathUnescape(version)
	return Product{Name: name, Version: version}, true
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
		if len(r.Products) == 0 {
			return true
		}
		pkg, _ := f.Metadata["package"].(string)
		ver, _ := f.Metadata["version"].(string)
		for _, p := range r.Products {
			if p.Name == pkg && (p.Version == "" || trimV(p.Version) == trimV(ver)) {
				return true
			}
		}
	}
	return false
}

func matchesVuln(f api.Finding, vulns []string) bool {
	for _, v := range vulns {
		if v != "" && (strings.EqualFold(v, f.CVE) || strings.EqualFold(v, f.RuleID)) {
			return true
		}
	}
	return false
}

func trimV(s string) string { return strings.TrimPrefix(s, "v") }

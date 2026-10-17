package vex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

const doc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    {"vulnerability": {"name": "CVE-2024-0001"}, "products": [{"@id": "pkg:golang/github.com/foo/bar@v1.2.3"}],
     "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
    {"vulnerability": {"name": "GHSA-aaaa"}, "status": "fixed"},
    {"vulnerability": {"name": "CVE-2024-0002"}, "status": "under_investigation"}
  ]
}`

func dep(id, cve, pkg, version string) api.Finding {
	return api.Finding{RuleID: id, CVE: cve, Metadata: map[string]any{"ecosystem": "go", "package": pkg, "version": version}}
}

func TestLoadAndFilter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.openvex.json")
	if err := os.WriteFile(p, []byte(doc), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadWithOptions([]string{p}, LoadOptions{AllowBroad: true})
	if err != nil {
		t.Fatal(err)
	}

	findings := []api.Finding{
		dep("GO-1", "CVE-2024-0001", "github.com/foo/bar", "v1.2.3"),   // suppressed: product + version match
		dep("GO-1", "CVE-2024-0001", "github.com/foo/bar", "v1.3.0"),   // kept: other version
		dep("GO-1", "CVE-2024-0001", "github.com/other/pkg", "v1.2.3"), // kept: other package
		dep("GHSA-aaaa", "", "anything", "1"),                          // suppressed: global, by OSV ID
		dep("GO-2", "CVE-2024-0002", "x", "1"),                         // kept: under_investigation
		dep("GO-3", "CVE-2024-0003", "x", "1"),                         // kept: unparseable product must not go global
	}
	kept, suppressed := Filter(findings[:5], rules)
	if len(suppressed) != 2 || len(kept) != 3 {
		t.Fatalf("suppressed=%d kept=%d: %+v", len(suppressed), len(kept), suppressed)
	}
	if _, err := Load([]string{p}); err == nil {
		t.Fatal("product-free statements must require explicit broad-scope authorization")
	}
}

func TestParsePURLScopedNPM(t *testing.T) {
	p, ok := parsePURL("pkg:npm/%40babel/core@7.0.0")
	if !ok || p.Ecosystem != "npm" || p.Name != "@babel/core" || p.Version != "7.0.0" {
		t.Fatalf("%+v %v", p, ok)
	}
}

func TestSC071_VEXProductIdentityIncludesEcosystemAndCanonicalName(t *testing.T) {
	cases := []struct {
		name           string
		purl           string
		finding        api.Finding
		wantSuppressed bool
	}{
		{name: "Go module", purl: "pkg:golang/github.com/acme/lib@v1.2.3", finding: dep("GO-1", "CVE-1", "github.com/acme/lib", "v1.2.3"), wantSuppressed: true},
		{name: "same name different ecosystem", purl: "pkg:golang/github.com/acme/lib@v1.2.3", finding: api.Finding{RuleID: "CVE-1", CVE: "CVE-1", Metadata: map[string]any{"ecosystem": "npm", "package": "github.com/acme/lib", "version": "v1.2.3"}}},
		{name: "missing ecosystem", purl: "pkg:golang/github.com/acme/lib@v1.2.3", finding: api.Finding{RuleID: "GO-1", CVE: "CVE-1", Metadata: map[string]any{"package": "github.com/acme/lib", "version": "v1.2.3"}}},
		{name: "Maven group artifact", purl: "pkg:maven/org.example/demo@2.0", finding: api.Finding{RuleID: "CVE-1", CVE: "CVE-1", Metadata: map[string]any{"ecosystem": "maven", "package": "org.example:demo", "version": "2.0"}}, wantSuppressed: true},
		{name: "scoped npm encoding", purl: "pkg:npm/%40acme/demo@2.0", finding: api.Finding{RuleID: "CVE-1", CVE: "CVE-1", Metadata: map[string]any{"ecosystem": "npm", "package": "@acme/demo", "version": "2.0"}}, wantSuppressed: true},
		{name: "normalized PyPI name", purl: "pkg:pypi/zope_interface@5.0", finding: api.Finding{RuleID: "CVE-1", CVE: "CVE-1", Metadata: map[string]any{"ecosystem": "pip", "package": "zope-interface", "version": "5.0"}}, wantSuppressed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := Rule{Vulns: []string{"CVE-1"}, Products: []Product{mustPURL(t, tc.purl)}}
			kept, suppressed := Filter([]api.Finding{tc.finding}, []Rule{rule})
			if got := len(suppressed) == 1; got != tc.wantSuppressed {
				t.Fatalf("suppressed=%v want=%v, kept=%+v", got, tc.wantSuppressed, kept)
			}
		})
	}
}

func TestSC072_VEXDoesNotDiscardQualifiersOrSubpath(t *testing.T) {
	for _, raw := range []string{
		"pkg:npm/%40acme/demo@2.0?arch=x64",
		"pkg:golang/github.com/acme/lib@v1.2.3#internal/pkg",
		"pkg:golang/github.com%2Facme/lib@v1.2.3",
		"pkg:pypi/team/package@1.0",
		"pkg:maven/org/example/demo@1.0",
		"pkg:golang/module@v1.0",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, ok := parsePURL(raw); ok {
				t.Fatalf("unsupported identity attributes must not be silently discarded: %s", raw)
			}
			path := filepath.Join(t.TempDir(), "qualified.json")
			body := `{"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"` + raw + `"}],"status":"not_affected"}]}`
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load([]string{path}); err == nil {
				t.Fatalf("unsupported identity attributes must produce a visible load error: %s", raw)
			}
		})
	}
}

func TestSC073_BroadVEXRequiresExplicitAuthorization(t *testing.T) {
	p := filepath.Join(t.TempDir(), "broad.json")
	if err := os.WriteFile(p, []byte(`{"statements":[{"vulnerability":{"name":"CVE-1"},"status":"fixed"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load([]string{p}); err == nil {
		t.Fatal("product-free statement must be rejected without explicit broad-scope authorization")
	}
	rules, err := LoadWithOptions([]string{p}, LoadOptions{AllowBroad: true})
	if err != nil {
		t.Fatal(err)
	}
	_, suppressed := Filter([]api.Finding{dep("CVE-1", "", "pkg", "1")}, rules)
	if len(suppressed) != 1 {
		t.Fatalf("authorized broad rule should apply, got %+v", suppressed)
	}
}

func TestSC074_VEXAliasesMatchOnlyWithinScopedProduct(t *testing.T) {
	rule := Rule{Vulns: []string{"OSV-1", "GHSA-aaaa"}, Products: []Product{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}}
	findings := []api.Finding{
		{RuleID: "OSV-1", Metadata: map[string]any{"ecosystem": "npm", "package": "lodash", "version": "4.17.21"}},
		{RuleID: "GHSA-aaaa", Metadata: map[string]any{"ecosystem": "npm", "package": "other", "version": "4.17.21"}},
		{RuleID: "GHSA-aaaa"},
		{RuleID: "CVE-2", Metadata: map[string]any{"ecosystem": "npm", "package": "lodash", "version": "4.17.21"}},
	}
	kept, suppressed := Filter(findings, []Rule{rule})
	if len(suppressed) != 1 || suppressed[0].RuleID != "OSV-1" || len(kept) != 3 {
		t.Fatalf("aliases must stay constrained to fully identified package instance: kept=%+v suppressed=%+v", kept, suppressed)
	}
}

func TestVEXRejectsInvalidProductPURL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(p, []byte(`{"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"not-a-purl"}],"status":"not_affected"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load([]string{p}); err == nil {
		t.Fatal("invalid product PURL must error instead of being silently ignored")
	}
}

func TestVEXReadsPURLFromOpenVEXProductIdentifiers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "identifiers.json")
	body := `{"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"identifiers":{"purl":"pkg:npm/lodash@4.17.21"}}],"status":"fixed"}]}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := Load([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	_, suppressed := Filter([]api.Finding{api.Finding{RuleID: "CVE-1", Metadata: map[string]any{"ecosystem": "npm", "package": "lodash", "version": "4.17.21"}}}, rules)
	if len(suppressed) != 1 {
		t.Fatalf("OpenVEX identifiers.purl must be used for product matching, got %+v", suppressed)
	}
}

func mustPURL(t *testing.T, raw string) Product {
	t.Helper()
	p, ok := parsePURL(raw)
	if !ok {
		t.Fatalf("parsePURL(%q) rejected", raw)
	}
	return p
}

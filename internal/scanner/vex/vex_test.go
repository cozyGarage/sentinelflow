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
    {"vulnerability": {"name": "CVE-2024-0002"}, "status": "under_investigation"},
    {"vulnerability": {"name": "CVE-2024-0003"}, "products": [{"@id": "not-a-purl"}], "status": "not_affected"}
  ]
}`

func dep(id, cve, pkg, version string) api.Finding {
	return api.Finding{RuleID: id, CVE: cve, Metadata: map[string]any{"package": pkg, "version": version}}
}

func TestLoadAndFilter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.openvex.json")
	if err := os.WriteFile(p, []byte(doc), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := Load([]string{p})
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
	kept, suppressed := Filter(findings, rules)
	if len(suppressed) != 2 || len(kept) != 4 {
		t.Fatalf("suppressed=%d kept=%d: %+v", len(suppressed), len(kept), suppressed)
	}
}

func TestParsePURLScopedNPM(t *testing.T) {
	p, ok := parsePURL("pkg:npm/%40babel/core@7.0.0?arch=x")
	if !ok || p.Name != "@babel/core" || p.Version != "7.0.0" {
		t.Fatalf("%+v %v", p, ok)
	}
}

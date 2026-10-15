package dependencies

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// A govulncheck -json stream: GO-1 is called (symbol-level trace), GO-2 is
// only required (module-level trace), GO-3 is called and aliased to a CVE.
const fakeGovulncheck = `#!/bin/sh
cat <<'JSON'
{"config":{"scan_level":"symbol"}}
{"osv":{"id":"GO-1","aliases":["CVE-1"]}}
{"osv":{"id":"GO-2"}}
{"osv":{"id":"GO-3","aliases":["CVE-3"]}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","package":"m/p","function":"F"}]}}
{"finding":{"osv":"GO-2","trace":[{"module":"m2"}]}}
{"finding":{"osv":"GO-3","trace":[{"module":"m3","package":"m3/p","function":"G","receiver":"*T"}]}}
JSON
exit 3
`

func TestAnnotateGoReachability(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "govulncheck")
	if err := os.WriteFile(bin, []byte(fakeGovulncheck), 0755); err != nil {
		t.Fatal(err)
	}
	old := GovulncheckBin
	GovulncheckBin = bin
	defer func() { GovulncheckBin = old }()

	goDep := func(rule, cve string) api.Finding {
		return api.Finding{Scanner: "dependencies", RuleID: rule, CVE: cve,
			Location: api.Location{File: "svc/go.sum"}, Metadata: map[string]any{"ecosystem": "go"}}
	}
	findings := []api.Finding{
		goDep("GO-1", ""),
		goDep("GO-2", ""),
		goDep("GHSA-x", "CVE-3"), // matched through the GO-3 alias
		goDep("GO-9", ""),        // not reported by govulncheck at all
		{Scanner: "dependencies", RuleID: "GO-1", Metadata: map[string]any{"ecosystem": "npm"}},
	}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err != nil {
		t.Fatal(err)
	}
	want := []*bool{ptr(true), ptr(false), ptr(true), ptr(false), nil}
	for i, w := range want {
		got := findings[i].Reachable
		if (got == nil) != (w == nil) || (got != nil && *got != *w) {
			t.Errorf("finding %d (%s): reachable=%v, want %v", i, findings[i].RuleID, deref(got), deref(w))
		}
	}
}

func TestAnnotateGoReachabilityMissingBinary(t *testing.T) {
	old := GovulncheckBin
	GovulncheckBin = "definitely-not-installed-govulncheck"
	defer func() { GovulncheckBin = old }()
	f := []api.Finding{{Scanner: "dependencies", RuleID: "GO-1", Location: api.Location{File: "go.mod"}, Metadata: map[string]any{"ecosystem": "go"}}}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), f); err != ErrGovulncheckMissing {
		t.Fatalf("want ErrGovulncheckMissing, got %v", err)
	}
}

func ptr(b bool) *bool { return &b }

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

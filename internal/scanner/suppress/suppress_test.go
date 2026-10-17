package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestFilterSameLineAndPreviousLine(t *testing.T) {
	dir := t.TempDir()
	src := `package p
func a() {
	x := eval(y) // sentinelflow:ignore xss-eval -- test
}
// sentinelflow:ignore path-traversal -- prev
func b() { _ = os.Open("../etc/passwd") }
func c() { x := eval(z) }
`
	path := filepath.Join(dir, "app.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []api.Finding{
		{RuleID: "xss-eval", Location: api.Location{File: "app.go", StartLine: 3}},
		{RuleID: "path-traversal", Location: api.Location{File: "app.go", StartLine: 6}},
		{RuleID: "xss-eval", Location: api.Location{File: "app.go", StartLine: 7}},
	}
	kept, suppressed := Filter(findings, dir)
	if len(suppressed) != 2 {
		t.Fatalf("suppressed = %d, want 2", len(suppressed))
	}
	if len(kept) != 1 || kept[0].Location.StartLine != 7 {
		t.Fatalf("kept = %+v", kept)
	}
}

func TestFilterStarIgnoresAllRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("// sentinelflow:ignore *\nbad()\n"), 0644); err != nil {
		t.Fatal(err)
	}
	kept, suppressed := Filter([]api.Finding{
		{RuleID: "anything", Location: api.Location{File: "x.go", StartLine: 2}},
	}, dir)
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Fatalf("kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}

func TestSC077_IgnoreDirectiveMustAppearInCommentText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.go")
	if err := os.WriteFile(path, []byte("value := `sentinelflow:ignore * -- looks like a directive`\n"), 0600); err != nil {
		t.Fatal(err)
	}
	kept, suppressed := Filter([]api.Finding{{RuleID: "rule", Location: api.Location{File: "x.go", StartLine: 1}}}, dir)
	if len(kept) != 1 || len(suppressed) != 0 {
		t.Fatalf("literal text suppressed finding: kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}

func TestSC077_StrictModeRequiresSpecificRuleAndReason(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("bad() // sentinelflow:ignore rule\n"), 0600); err != nil {
		t.Fatal(err)
	}
	finding := api.Finding{RuleID: "rule", Location: api.Location{File: "x.go", StartLine: 1}}
	kept, suppressed, err := FilterWithOptions([]api.Finding{finding}, dir, true)
	if err == nil || len(suppressed) != 0 || len(kept) != 1 || !strings.Contains(err.Error(), "non-empty reason") {
		t.Fatalf("strict reasonless directive: kept=%d suppressed=%d err=%v", len(kept), len(suppressed), err)
	}
	if _, suppressed := Filter([]api.Finding{finding}, dir); len(suppressed) != 1 {
		t.Fatal("legacy mode must preserve reasonless compatibility")
	}
}

func TestSC079_InlineIgnoreCannotReadOutsideScanRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.go")
	if err := os.WriteFile(outside, []byte("// sentinelflow:ignore * -- outside\ncode()\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../outside.go", outside} {
		_, suppressed := Filter([]api.Finding{{RuleID: "rule", Location: api.Location{File: rel, StartLine: 2}}}, root)
		if len(suppressed) != 0 {
			t.Fatalf("outside path %q suppressed a finding", rel)
		}
	}
	link := filepath.Join(root, "linked.go")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, suppressed := Filter([]api.Finding{{RuleID: "rule", Location: api.Location{File: "linked.go", StartLine: 2}}}, root)
	if len(suppressed) != 0 {
		t.Fatal("symlink escaping scan root suppressed a finding")
	}
}

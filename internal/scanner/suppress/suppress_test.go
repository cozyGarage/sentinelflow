package suppress

import (
	"os"
	"path/filepath"
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

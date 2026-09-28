package diff

import (
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestParseUnifiedAndFilter(t *testing.T) {
	text := `diff --git a/app.go b/app.go
--- a/app.go
+++ b/app.go
@@ -10,0 +11,2 @@
+secret := "AKIAIOSFODNN7EXAMPLE"
+other := 1
diff --git a/skip.go b/skip.go
--- a/skip.go
+++ b/skip.go
@@ -1 +1 @@
-old
+new
`
	changed := ParseUnified(text)
	if _, ok := changed["app.go"]; !ok {
		t.Fatalf("expected app.go in diff, got %+v", changed)
	}
	findings := []api.Finding{
		{ID: "on-diff", Location: api.Location{File: "app.go", StartLine: 11}},
		{ID: "off-diff", Location: api.Location{File: "app.go", StartLine: 3}},
		{ID: "other-file", Location: api.Location{File: "lib.go", StartLine: 1}},
		{ID: "no-file", Location: api.Location{}},
	}
	kept := Filter(findings, changed)
	ids := map[string]bool{}
	for _, f := range kept {
		ids[f.ID] = true
	}
	if !ids["on-diff"] {
		t.Fatal("expected finding on added line")
	}
	if ids["off-diff"] {
		t.Fatal("line 3 was not in the hunk")
	}
	if ids["other-file"] {
		t.Fatal("lib.go was not in the diff")
	}
	if !ids["no-file"] {
		t.Fatal("findings without a file should be kept")
	}
}

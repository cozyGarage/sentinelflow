package baseline

import (
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestFilterBaselinedFindings(t *testing.T) {
	findings := []api.Finding{
		{ID: "SEC-1", RuleID: "aws-access-key", Title: "AWS Key", Location: api.Location{File: "config.go", StartLine: 1}},
		{ID: "SEC-2", RuleID: "github-token", Title: "GitHub Token", Location: api.Location{File: "app.go", StartLine: 5}},
	}

	bl := Generate(findings[:1])

	filtered := Filter(findings, bl)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(filtered))
	}
	if filtered[0].ID != "SEC-2" {
		t.Errorf("expected SEC-2, got %s", filtered[0].ID)
	}
}

func TestFilterByIDDoesNotCrossFilesWhenIDsDiffer(t *testing.T) {
	a := api.Finding{
		ID: "IAC-DOCKER-latest-tag-aaaa-1", RuleID: "latest-tag",
		Location: api.Location{File: "Dockerfile", StartLine: 1},
	}
	b := api.Finding{
		ID: "IAC-DOCKER-latest-tag-bbbb-1", RuleID: "latest-tag",
		Location: api.Location{File: "app.dockerfile", StartLine: 1},
	}
	bl := &File{Findings: []Entry{{ID: a.ID, RuleID: a.RuleID, File: a.Location.File, Hash: HashFinding(a)}}}
	filtered := Filter([]api.Finding{a, b}, bl)
	if len(filtered) != 1 || filtered[0].ID != b.ID {
		t.Fatalf("baselining one file's ID must not suppress the other file, got %+v", filtered)
	}
}

func TestFilterDoesNotSuppressNewFindingSameRuleFile(t *testing.T) {
	a := api.Finding{
		ID: "SEC-aws-1", RuleID: "aws-access-key", Title: "AWS Key",
		Location:  api.Location{File: "config.go", StartLine: 1, Snippet: "key = \"first\""},
		ValueHash: "aaaa",
	}
	b := api.Finding{
		ID: "SEC-aws-20", RuleID: "aws-access-key", Title: "AWS Key",
		Location:  api.Location{File: "config.go", StartLine: 20, Snippet: "key = \"other\""},
		ValueHash: "bbbb",
	}
	bl := Generate([]api.Finding{a})
	filtered := Filter([]api.Finding{a, b}, bl)
	if len(filtered) != 1 || filtered[0].ID != b.ID {
		t.Fatalf("new finding same rule/file must not be suppressed by rule:file, got %+v", filtered)
	}
}

func TestSC024_BaselineDoesNotCollapsePackageInstances(t *testing.T) {
	old := api.Finding{
		ID: "DEP-npm-old", RuleID: "OSV-1", Title: "Vulnerable dependency: lodash",
		Location: api.Location{File: "package-lock.json", Snippet: "lodash@4.17.20 (node_modules/a/node_modules/lodash)"},
		Metadata: map[string]any{"package": "lodash", "version": "4.17.20", "install_path": "node_modules/a/node_modules/lodash"},
	}
	other := api.Finding{
		ID: "DEP-npm-other", RuleID: "OSV-1", Title: "Vulnerable dependency: lodash",
		Location: api.Location{File: "package-lock.json", Snippet: "lodash@4.17.21 (node_modules/lodash)"},
		Metadata: map[string]any{"package": "lodash", "version": "4.17.21", "install_path": "node_modules/lodash"},
	}
	filtered := Filter([]api.Finding{old, other}, Generate([]api.Finding{old}))
	if len(filtered) != 1 || filtered[0].ID != other.ID {
		t.Fatalf("baseline for one installed instance suppressed another: %+v", filtered)
	}
}

func TestSummarizeCountsSuppressedAndNew(t *testing.T) {
	findings := []api.Finding{
		{ID: "SEC-1", RuleID: "aws-access-key", Title: "AWS Key", Location: api.Location{File: "config.go", StartLine: 1}},
		{ID: "SEC-2", RuleID: "github-token", Title: "GitHub Token", Location: api.Location{File: "app.go", StartLine: 5}},
	}
	bl := Generate(findings[:1])
	filtered := Filter(findings, bl)
	summary := Summarize(findings, filtered)
	if summary.Total != 2 || summary.Suppressed != 1 || summary.New != 1 {
		t.Fatalf("summary = %+v, want total 2 suppressed 1 new 1", summary)
	}
	if summary.New != len(filtered) {
		t.Fatalf("new count %d must match filtered findings %d", summary.New, len(filtered))
	}
}

func TestSummarizeEmptyBaselineSuppressesNothing(t *testing.T) {
	findings := []api.Finding{
		{ID: "SEC-1", RuleID: "aws-access-key", Location: api.Location{File: "config.go", StartLine: 1}},
	}
	filtered := Filter(findings, &File{Version: "1.0"})
	summary := Summarize(findings, filtered)
	if summary.Total != 1 || summary.Suppressed != 0 || summary.New != 1 {
		t.Fatalf("empty baseline summary = %+v", summary)
	}
}

func TestFilterV2FingerprintSurvivesLineMove(t *testing.T) {
	a := api.Finding{
		ID: "SEC-1", RuleID: "aws-access-key", Title: "AWS Key",
		ValueHash: "deadbeef",
		Location:  api.Location{File: "config.go", StartLine: 1, Snippet: "AKIA***"},
	}
	moved := a
	moved.ID = "SEC-1-moved"
	moved.Location.StartLine = 80
	moved.Location.StartCol = 12

	bl := Generate([]api.Finding{a})
	if bl.Version != VersionV2 {
		t.Fatalf("expected v2 baseline, got %s", bl.Version)
	}
	if bl.Findings[0].Fingerprint == "" {
		t.Fatal("expected fingerprint on generated entry")
	}
	filtered := Filter([]api.Finding{moved}, bl)
	if len(filtered) != 0 {
		t.Fatalf("moved finding should still match v2 fingerprint, got %+v", filtered)
	}
}

func TestFilterExpiredEntryDoesNotSuppress(t *testing.T) {
	a := api.Finding{
		ID: "SEC-1", RuleID: "aws-access-key", Title: "AWS Key",
		ValueHash: "deadbeef",
		Location:  api.Location{File: "config.go", StartLine: 1, Snippet: "AKIA***"},
	}
	bl := Generate([]api.Finding{a})
	bl.Findings[0].Expires = "2000-01-01"
	filtered := Filter([]api.Finding{a}, bl)
	if len(filtered) != 1 {
		t.Fatalf("expired entry must not suppress, got %+v", filtered)
	}
}

func TestSC075_ExpiryBoundaryIsUTCAndMalformedExpiryDoesNotSuppress(t *testing.T) {
	finding := api.Finding{ID: "x", RuleID: "r", Location: api.Location{File: "x"}}
	base := &File{Findings: []Entry{{ID: "x", Expires: "2025-01-02"}}}
	cases := []struct {
		name           string
		now            time.Time
		wantSuppressed bool
	}{
		{name: "before expiry end", now: time.Date(2025, 1, 2, 23, 59, 59, 0, time.UTC), wantSuppressed: true},
		{name: "local time still inside UTC expiry day", now: time.Date(2025, 1, 3, 0, 30, 0, 0, time.FixedZone("plus-one", 3600)), wantSuppressed: true},
		{name: "at next midnight", now: time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC)},
		{name: "after next midnight", now: time.Date(2025, 1, 3, 0, 0, 1, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filtered := FilterAt([]api.Finding{finding}, base, tc.now)
			if got := len(filtered) == 0; got != tc.wantSuppressed {
				t.Fatalf("suppressed=%v want=%v", got, tc.wantSuppressed)
			}
		})
	}
	base.Findings[0].Expires = "2025-02-30"
	if filtered := FilterAt([]api.Finding{finding}, base, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)); len(filtered) != 1 {
		t.Fatalf("malformed expiry must fail open and retain finding, got %+v", filtered)
	}
}

func TestFilterLegacyRuleFileWhenNoIDOrHash(t *testing.T) {
	a := api.Finding{
		ID: "SEC-1", RuleID: "aws-access-key",
		Location: api.Location{File: "config.go", StartLine: 1},
	}
	b := api.Finding{
		ID: "SEC-2", RuleID: "aws-access-key",
		Location: api.Location{File: "config.go", StartLine: 20},
	}
	bl := &File{Findings: []Entry{{RuleID: "aws-access-key", File: "config.go"}}}
	filtered := Filter([]api.Finding{a, b}, bl)
	if len(filtered) != 0 {
		t.Fatalf("legacy rule:file entries should still suppress, got %+v", filtered)
	}
}

func TestFilterLegacyRuleFileUsesExactRuleAndFile(t *testing.T) {
	finding := api.Finding{
		ID: "SEC-1", RuleID: "r", Location: api.Location{File: "x:y", StartLine: 1},
	}
	bl := &File{Findings: []Entry{{RuleID: "r:x", File: "y"}}}

	filtered := Filter([]api.Finding{finding}, bl)
	if len(filtered) != 1 || filtered[0].ID != finding.ID {
		t.Fatalf("legacy entry for another rule/file pair must not suppress this finding, got %+v", filtered)
	}
}

package baseline

import (
	"testing"

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
		Location: api.Location{File: "config.go", StartLine: 1},
	}
	b := api.Finding{
		ID: "SEC-aws-20", RuleID: "aws-access-key", Title: "AWS Key",
		Location: api.Location{File: "config.go", StartLine: 20},
	}
	bl := Generate([]api.Finding{a})
	filtered := Filter([]api.Finding{a, b}, bl)
	if len(filtered) != 1 || filtered[0].ID != b.ID {
		t.Fatalf("new finding same rule/file must not be suppressed by rule:file, got %+v", filtered)
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

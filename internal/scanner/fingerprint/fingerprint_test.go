package fingerprint

import (
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestFingerprintIgnoresLineNumbers(t *testing.T) {
	a := api.Finding{
		RuleID: "aws-access-key",
		Title:  "Potential AWS Access Key ID detected",
		Location: api.Location{
			File:      "config.go",
			StartLine: 10,
			StartCol:  4,
			Snippet:   `key := "AKIA****************"`,
		},
		ValueHash: "abcd",
	}
	b := a
	b.Location.StartLine = 40
	b.Location.StartCol = 12
	if Of(a) != Of(b) {
		t.Fatalf("moving a finding must not change fingerprint: %s vs %s", Of(a), Of(b))
	}
}

func TestFingerprintChangesWithPathOrValue(t *testing.T) {
	base := api.Finding{
		RuleID:    "aws-access-key",
		ValueHash: "aaa",
		Location:  api.Location{File: "a.go", Snippet: "x"},
	}
	otherFile := base
	otherFile.Location.File = "b.go"
	otherVal := base
	otherVal.ValueHash = "bbb"
	if Of(base) == Of(otherFile) {
		t.Fatal("different files must not share a fingerprint")
	}
	if Of(base) == Of(otherVal) {
		t.Fatal("different values must not share a fingerprint")
	}
}

func TestEnsureFillsEmpty(t *testing.T) {
	findings := []api.Finding{{
		RuleID: "r", Location: api.Location{File: "f.go", Snippet: "body"},
	}}
	Ensure(findings)
	if findings[0].Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
	if Of(findings[0]) != findings[0].Fingerprint {
		t.Fatal("Ensure should be stable with Of")
	}
}

func TestSC078_FingerprintEncodingCannotCollideOnDelimiters(t *testing.T) {
	a := api.Finding{RuleID: "a|b", Location: api.Location{File: "c"}}
	b := api.Finding{RuleID: "a", Location: api.Location{File: "b|c"}}
	if Key(a) == Key(b) || Of(a) == Of(b) {
		t.Fatal("delimiter-bearing fields must not collide in fingerprint serialization")
	}
}

func TestSC078_FingerprintIncludesDependencyInstanceIdentity(t *testing.T) {
	a := api.Finding{RuleID: "OSV-1", Metadata: map[string]any{"ecosystem": "npm", "package": "widget", "version": "1.0.0"}}
	b := a
	b.Metadata = map[string]any{"ecosystem": "npm", "package": "widget", "version": "2.0.0"}
	if Of(a) == Of(b) {
		t.Fatal("distinct installed package versions must have distinct fingerprints")
	}
}

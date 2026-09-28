package cli

import (
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestDeduplicateFindingsUsesExactKeyFields(t *testing.T) {
	duplicate := api.Finding{
		ID: "id:part", Location: api.Location{File: "file", StartLine: 7}, Title: "first",
	}
	keyCollision := api.Finding{
		ID: "id", Location: api.Location{File: "part:file", StartLine: 7}, Title: "distinct",
	}
	duplicateAgain := duplicate
	duplicateAgain.Title = "later duplicate"

	got := deduplicateFindings([]api.Finding{duplicate, keyCollision, duplicateAgain})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 distinct keys", len(got))
	}
	if got[0].Title != "first" || got[1].Title != "distinct" {
		t.Fatalf("deduplication should preserve the first finding for each exact key, got %+v", got)
	}
}

package scanner

import (
	"context"
	"sort"

	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// enrichRisk sets EPSS and KEV on findings that carry a CVE. Lookup failures
// are returned as a warning; findings keep their severity either way.
func enrichRisk(ctx context.Context, findings []api.Finding) error {
	seen := map[string]bool{}
	var cves []string
	for _, f := range findings {
		if f.CVE != "" && !seen[f.CVE] {
			seen[f.CVE] = true
			cves = append(cves, f.CVE)
		}
	}
	if len(cves) == 0 {
		return nil
	}
	sort.Strings(cves)
	risk, err := vulndb.FetchRisk(ctx, nil, cves)
	for i := range findings {
		findings[i].EPSS = risk.EPSS[findings[i].CVE]
		findings[i].KEV = risk.KEV[findings[i].CVE]
	}
	return err
}

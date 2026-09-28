// Package suppress implements inline sentinelflow:ignore comments.
package suppress

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Directive matches:
//
//	sentinelflow:ignore <rule-id> [-- reason]
var directive = regexp.MustCompile(`(?i)sentinelflow:ignore\s+([A-Za-z0-9_.:/*-]+)(?:\s+--\s+(.*))?`)

type fileCache struct {
	lines map[string][]string
}

func (c *fileCache) linesOf(root, rel string) []string {
	if c.lines == nil {
		c.lines = map[string][]string{}
	}
	if cached, ok := c.lines[rel]; ok {
		return cached
	}
	path := rel
	if root != "" && !filepath.IsAbs(rel) {
		path = filepath.Join(root, rel)
	}
	f, err := os.Open(path)
	if err != nil {
		c.lines[rel] = nil
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	c.lines[rel] = out
	return out
}

// Filter drops findings whose source line (or the previous line) contains a
// matching sentinelflow:ignore directive. Findings without a file/line are kept.
func Filter(findings []api.Finding, root string) (kept, suppressed []api.Finding) {
	cache := &fileCache{}
	for _, f := range findings {
		if ignored(cache, root, f) {
			suppressed = append(suppressed, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

func ignored(cache *fileCache, root string, f api.Finding) bool {
	if f.Location.File == "" || f.Location.StartLine <= 0 {
		return false
	}
	lines := cache.linesOf(root, f.Location.File)
	if len(lines) == 0 {
		return false
	}
	idx := f.Location.StartLine - 1
	if idx < 0 || idx >= len(lines) {
		return false
	}
	if matches(lines[idx], f.RuleID) {
		return true
	}
	if idx > 0 && matches(lines[idx-1], f.RuleID) {
		return true
	}
	return false
}

func matches(line, ruleID string) bool {
	m := directive.FindStringSubmatch(line)
	if len(m) < 2 {
		return false
	}
	want := strings.TrimSpace(m[1])
	if want == "*" || strings.EqualFold(want, "all") {
		return true
	}
	return strings.EqualFold(want, strings.TrimSpace(ruleID))
}

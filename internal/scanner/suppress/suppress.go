// Package suppress implements inline sentinelflow:ignore comments.
package suppress

import (
	"bufio"
	"fmt"
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
	path, ok := resolveUnderRoot(root, rel)
	if !ok {
		c.lines[rel] = nil
		return nil
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
	kept, suppressed, _ = FilterWithOptions(findings, root, false)
	return kept, suppressed
}

// FilterWithOptions applies inline directives. In strict mode, applicable
// wildcard and reasonless directives are errors and do not suppress findings.
func FilterWithOptions(findings []api.Finding, root string, strict bool) (kept, suppressed []api.Finding, err error) {
	cache := &fileCache{}
	for _, f := range findings {
		matched, invalid := ignored(cache, root, f, strict)
		if invalid {
			return findings, nil, fmt.Errorf("inline ignore for rule %q requires a specific rule and a non-empty reason", f.RuleID)
		}
		if matched {
			suppressed = append(suppressed, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed, nil
}

func ignored(cache *fileCache, root string, f api.Finding, strict bool) (bool, bool) {
	if f.Location.File == "" || f.Location.StartLine <= 0 {
		return false, false
	}
	lines := cache.linesOf(root, f.Location.File)
	if len(lines) == 0 {
		return false, false
	}
	idx := f.Location.StartLine - 1
	if idx < 0 || idx >= len(lines) {
		return false, false
	}
	if matched, invalid := matches(lines[idx], f.RuleID, strict); matched || invalid {
		return matched, invalid
	}
	if idx > 0 {
		return matches(lines[idx-1], f.RuleID, strict)
	}
	return false, false
}

func matches(line, ruleID string, strict bool) (bool, bool) {
	comment := commentPart(line)
	m := directive.FindStringSubmatch(comment)
	if len(m) < 2 {
		return false, false
	}
	want := strings.TrimSpace(m[1])
	if strict && (want == "*" || strings.EqualFold(want, "all") || len(m) < 3 || strings.TrimSpace(m[2]) == "") {
		if want == "*" || strings.EqualFold(want, "all") || strings.EqualFold(want, strings.TrimSpace(ruleID)) {
			return false, true
		}
	}
	if want == "*" || strings.EqualFold(want, "all") {
		return true, false
	}
	return strings.EqualFold(want, strings.TrimSpace(ruleID)), false
}

func commentPart(line string) string {
	quote := rune(0)
	escaped := false
	for i, r := range line {
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' || r == '`' {
			quote = r
			continue
		}
		for _, marker := range []string{"//", "#", "--", "/*", "<!--"} {
			if strings.HasPrefix(line[i:], marker) {
				return line[i:]
			}
		}
	}
	return ""
}

func resolveUnderRoot(root, rel string) (string, bool) {
	// Findings use slash paths; reject absolute, drive-qualified, and traversal
	// paths before joining. Symlinks are resolved and checked against root too.
	rel = strings.ReplaceAll(rel, `\`, "/")
	if filepath.IsAbs(rel) || (len(rel) >= 2 && rel[1] == ':') {
		return "", false
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return "", false
		}
	}
	if root == "" {
		return rel, true
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	path := filepath.Join(rootAbs, filepath.FromSlash(rel))
	resolvedRoot, rootErr := filepath.EvalSymlinks(rootAbs)
	resolvedPath, pathErr := filepath.EvalSymlinks(path)
	if rootErr == nil && pathErr == nil {
		r, err := filepath.Rel(resolvedRoot, resolvedPath)
		if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", false
		}
	}
	r, err := filepath.Rel(rootAbs, path)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	return path, true
}

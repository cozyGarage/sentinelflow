// Package diff filters findings to git changed files and lines.
package diff

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Range is a 1-indexed inclusive line range in a changed file.
type Range struct {
	Start int
	End   int
}

// Spec describes a git diff used to filter findings.
type Spec struct {
	Root   string
	Base   string // rev for --diff-base; empty with Staged uses the index
	Staged bool
}

// Changed maps slash-normalized relative paths to changed line ranges.
// A nil/empty range list means "any line in this file".
type Changed map[string][]Range

// Collect runs git diff and returns changed paths relative to root.
func Collect(spec Spec) (Changed, error) {
	if spec.Root == "" {
		return nil, fmt.Errorf("diff: empty root")
	}
	args := []string{"diff", "--unified=0", "--no-color", "--no-ext-diff"}
	if spec.Staged {
		args = append(args, "--cached")
	}
	if spec.Base != "" {
		args = append(args, spec.Base)
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = spec.Root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	return ParseUnified(string(out)), nil
}

// ParseUnified parses `git diff --unified=0` output.
func ParseUnified(diffText string) Changed {
	changed := Changed{}
	var current string
	for _, line := range strings.Split(diffText, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			current = strings.TrimPrefix(line, "+++ b/")
			current = filepath.ToSlash(current)
			if _, ok := changed[current]; !ok {
				changed[current] = nil
			}
			continue
		}
		if strings.HasPrefix(line, "+++ /dev/null") {
			current = ""
			continue
		}
		if current == "" || !strings.HasPrefix(line, "@@") {
			continue
		}
		// @@ -l,s +l,s @@
		plus := line
		if i := strings.Index(plus, "+"); i >= 0 {
			plus = plus[i+1:]
		}
		plus = strings.Fields(plus)[0]
		start, count := parseHunk(plus)
		if count == 0 {
			// Pure deletion: still mark the file, no added lines.
			continue
		}
		end := start + count - 1
		changed[current] = append(changed[current], Range{Start: start, End: end})
	}
	return changed
}

func parseHunk(spec string) (start, count int) {
	spec = strings.TrimSuffix(spec, "@@")
	parts := strings.SplitN(spec, ",", 2)
	start, _ = strconv.Atoi(parts[0])
	count = 1
	if len(parts) == 2 {
		count, _ = strconv.Atoi(parts[1])
	}
	return start, count
}

// Filter keeps findings whose file is in the diff. If the file has line
// ranges, the finding's start line must overlap one of them. Findings
// without a file (e.g. container image CVEs) are kept.
func Filter(findings []api.Finding, changed Changed) []api.Finding {
	if len(changed) == 0 {
		return nil
	}
	var out []api.Finding
	for _, f := range findings {
		file := filepath.ToSlash(f.Location.File)
		if file == "" {
			out = append(out, f)
			continue
		}
		ranges, ok := changed[file]
		if !ok {
			// Also try base name matches when git reports a different prefix.
			ok = false
			for p, r := range changed {
				if filepath.Base(p) == filepath.Base(file) && (strings.HasSuffix(file, p) || strings.HasSuffix(p, file)) {
					ranges = r
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if len(ranges) == 0 || f.Location.StartLine <= 0 {
			out = append(out, f)
			continue
		}
		if overlaps(f.Location.StartLine, f.Location.EndLine, ranges) {
			out = append(out, f)
		}
	}
	return out
}

func overlaps(start, end int, ranges []Range) bool {
	if end <= 0 {
		end = start
	}
	for _, r := range ranges {
		if start <= r.End && end >= r.Start {
			return true
		}
	}
	return false
}

// FileList returns the unique relative paths in the diff.
func FileList(changed Changed) []string {
	out := make([]string, 0, len(changed))
	for p := range changed {
		out = append(out, p)
	}
	return out
}

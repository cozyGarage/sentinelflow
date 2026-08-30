// Package filter provides shared file skip logic for scanners.
package filter

import (
	"path/filepath"
	"strings"
)

// ShouldSkip returns true if a file should be excluded from scanning.
// Hardcoded skips are limited to Go testdata trees. Test-file globs (e.g.
// **/*_test.go) belong in caller config — secrets defaults, scanners.exclude —
// so clearing allowlist/exclude can still scan tests when desired.
func ShouldSkip(path string, allowlist []string) bool {
	normalized := filepath.ToSlash(path)
	base := filepath.Base(normalized)

	if strings.Contains(normalized, "/testdata/") {
		return true
	}

	for _, pattern := range allowlist {
		if matchPattern(normalized, base, filepath.ToSlash(pattern)) {
			return true
		}
	}
	return false
}

// IsBundledSampleDir reports whether dirPath is a repo sample tree that should
// be skipped when scanning a larger target. Only test/fixtures and
// examples/demo-project qualify — not arbitrary directories named "fixtures".
func IsBundledSampleDir(scanRoot, dirPath string) bool {
	root := filepath.Clean(scanRoot)
	dir := filepath.Clean(dirPath)
	if dir == root {
		return false
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	rel = filepath.ToSlash(rel)
	switch {
	case rel == "test/fixtures", strings.HasPrefix(rel, "test/fixtures/"):
		return true
	case rel == "examples/demo-project", strings.HasPrefix(rel, "examples/demo-project/"):
		return true
	default:
		return false
	}
}

func matchPattern(path, base, pattern string) bool {
	if path == pattern {
		return true
	}
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}
	if matched, _ := filepath.Match(pattern, base); matched {
		return true
	}

	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			if prefix != "" && !strings.HasPrefix(path, prefix+"/") && path != prefix {
				return false
			}
			if suffix == "" {
				return true
			}
			if strings.HasSuffix(path, suffix) || strings.Contains(path, "/"+suffix) {
				return true
			}
			// Support globs in the suffix (e.g. **/*_test.go).
			if matched, _ := filepath.Match(suffix, base); matched {
				return true
			}
			if matched, _ := filepath.Match(suffix, path); matched {
				return true
			}
			// Match suffix against any path segment suffix (a/b/*_test.go style).
			if strings.Contains(suffix, "*") {
				for _, seg := range strings.Split(path, "/") {
					if matched, _ := filepath.Match(suffix, seg); matched {
						return true
					}
				}
			}
		}
	}

	return false
}

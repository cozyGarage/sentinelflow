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
		return matchDoublestar(path, pattern)
	}
	return false
}

// matchDoublestar implements a small subset of doublestar globs used in config:
//   **/*_test.go, **/testdata/**, docs/**, foo/**/bar
func matchDoublestar(path, pattern string) bool {
	path = strings.Trim(filepath.ToSlash(path), "/")
	pattern = strings.Trim(filepath.ToSlash(pattern), "/")
	if pattern == "**" || pattern == "" {
		return true
	}

	pathParts := splitPath(path)
	patParts := splitPath(pattern)
	return matchParts(pathParts, patParts)
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func matchParts(pathParts, patParts []string) bool {
	i, j := 0, 0
	for i < len(pathParts) || j < len(patParts) {
		if j < len(patParts) && patParts[j] == "**" {
			// Trailing ** matches the rest
			if j == len(patParts)-1 {
				return true
			}
			// Try consuming zero or more path segments until the remainder matches
			restPat := patParts[j+1:]
			for k := i; k <= len(pathParts); k++ {
				if matchParts(pathParts[k:], restPat) {
					return true
				}
			}
			return false
		}
		if i >= len(pathParts) || j >= len(patParts) {
			// Allow trailing empty only via ** (handled above)
			return i >= len(pathParts) && j >= len(patParts)
		}
		if matched, _ := filepath.Match(patParts[j], pathParts[i]); !matched {
			return false
		}
		i++
		j++
	}
	return i == len(pathParts) && j == len(patParts)
}

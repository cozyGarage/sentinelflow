// Package fingerprint builds line-independent finding identities.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Of returns a stable fingerprint. It prefers Finding.Fingerprint, then
// ValueHash, then a hash of rule + relative path + artifact path +
// normalized snippet. Line and column numbers are never included.
func Of(f api.Finding) string {
	if fp := strings.TrimSpace(f.Fingerprint); fp != "" {
		return fp
	}
	key := Key(f)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

// Key is the raw material hashed by Of (exported for tests).
func Key(f api.Finding) string {
	path := filepath.ToSlash(f.Location.File)
	artifact := filepath.ToSlash(f.Location.ArtifactPath)
	payload := strings.TrimSpace(f.ValueHash)
	if payload == "" {
		payload = normalizeSnippet(f.Location.Snippet)
	}
	if payload == "" {
		payload = strings.TrimSpace(f.Title)
	}
	return strings.Join([]string{
		strings.TrimSpace(f.RuleID),
		path,
		artifact,
		payload,
		strings.TrimSpace(f.CVE),
	}, "|")
}

// ValueHash returns a hex SHA-256 prefix of a secret or component value.
func ValueHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func normalizeSnippet(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if prevSpace {
				continue
			}
			b.WriteByte(' ')
			prevSpace = true
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

// Ensure sets Fingerprint on every finding that lacks one.
func Ensure(findings []api.Finding) {
	for i := range findings {
		if findings[i].Fingerprint == "" {
			findings[i].Fingerprint = Of(findings[i])
		}
	}
}

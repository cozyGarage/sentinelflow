// Package baseline provides finding baseline/allowlist management
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"gopkg.in/yaml.v3"
)

const (
	DefaultPath = ".sentinelflow/baseline.yaml"
	VersionV1   = "1.0"
	VersionV2   = "2.0"
)

// File represents a baseline file
type File struct {
	Version  string  `yaml:"version"`
	Findings []Entry `yaml:"findings"`
}

// Entry represents a baselined finding
type Entry struct {
	ID          string `yaml:"id,omitempty"`
	File        string `yaml:"file,omitempty"`
	RuleID      string `yaml:"rule_id,omitempty"`
	Hash        string `yaml:"hash,omitempty"`
	Fingerprint string `yaml:"fingerprint,omitempty"`
	Reason      string `yaml:"reason,omitempty"`
	Expires     string `yaml:"expires,omitempty"` // YYYY-MM-DD
}

// Load reads a baseline file from disk
func Load(path string) (*File, error) {
	if path == "" {
		path = DefaultPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Version: VersionV2, Findings: []Entry{}}, nil
		}
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}
	if f.Version == "" {
		f.Version = VersionV1
	}

	return &f, nil
}

// Save writes a baseline file to disk
func Save(path string, f *File) error {
	if path == "" {
		path = DefaultPath
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create baseline directory: %w", err)
	}

	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// Generate creates a v2 baseline from scan findings
func Generate(findings []api.Finding) *File {
	entries := make([]Entry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, Entry{
			ID:          f.ID,
			File:        f.Location.File,
			RuleID:      f.RuleID,
			Hash:        HashFinding(f),
			Fingerprint: fingerprint.Of(f),
		})
	}
	return &File{Version: VersionV2, Findings: entries}
}

// HashFinding creates a v1 (line-sensitive) hash for a finding.
// Kept so existing baseline.yaml files continue to match.
func HashFinding(f api.Finding) string {
	key := fmt.Sprintf("%s|%s|%s|%d|%d", f.RuleID, f.Location.File, f.Title, f.Location.StartLine, f.Location.StartCol)
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:8])
}

// Summary counts findings before and after baseline filtering.
type Summary struct {
	Total      int
	Suppressed int
	New        int
}

// Summarize reports how many findings a baseline kept versus suppressed.
// New equals len(after), the set the fail gate sees.
func Summarize(before, after []api.Finding) Summary {
	total := len(before)
	newCount := len(after)
	suppressed := total - newCount
	if suppressed < 0 {
		suppressed = 0
	}
	return Summary{Total: total, Suppressed: suppressed, New: newCount}
}

func entryExpired(e Entry, now time.Time) bool {
	raw := strings.TrimSpace(e.Expires)
	if raw == "" {
		return false
	}
	day, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return false
	}
	// Expires at the end of the given day (inclusive until next midnight UTC).
	return now.UTC().After(day.UTC().Add(24 * time.Hour))
}

// Filter removes baselined findings from the result set
func Filter(findings []api.Finding, baseline *File) []api.Finding {
	if baseline == nil || len(baseline.Findings) == 0 {
		return findings
	}

	type legacyKey struct {
		ruleID string
		file   string
	}

	now := time.Now()
	baselined := make(map[string]struct{}, len(baseline.Findings)*3)
	var legacy map[legacyKey]struct{}
	for _, e := range baseline.Findings {
		if entryExpired(e, now) {
			continue
		}
		if e.Fingerprint != "" {
			baselined["fp:"+e.Fingerprint] = struct{}{}
		}
		if e.Hash != "" {
			baselined[e.Hash] = struct{}{}
		}
		if e.ID != "" {
			baselined["id:"+e.ID] = struct{}{}
		}
		// Legacy entries without ID/hash/fingerprint: suppress by rule+file only.
		if e.ID == "" && e.Hash == "" && e.Fingerprint == "" && e.RuleID != "" && e.File != "" {
			if legacy == nil {
				legacy = make(map[legacyKey]struct{})
			}
			legacy[legacyKey{ruleID: e.RuleID, file: e.File}] = struct{}{}
		}
	}

	var filtered []api.Finding
	for _, f := range findings {
		if f.Fingerprint != "" {
			if _, ok := baselined["fp:"+f.Fingerprint]; ok {
				continue
			}
		}
		computedFingerprint := fingerprint.Of(f)
		if computedFingerprint != f.Fingerprint {
			if _, ok := baselined["fp:"+computedFingerprint]; ok {
				continue
			}
		}
		if _, ok := baselined[HashFinding(f)]; ok {
			continue
		}
		if f.ID != "" {
			if _, ok := baselined["id:"+f.ID]; ok {
				continue
			}
		}
		if len(legacy) > 0 {
			if _, ok := legacy[legacyKey{ruleID: f.RuleID, file: f.Location.File}]; ok {
				continue
			}
		}
		filtered = append(filtered, f)
	}

	return filtered
}

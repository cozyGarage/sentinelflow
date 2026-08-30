// Package baseline provides finding baseline/allowlist management
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cozygarage/sentinelflow/pkg/api"
	"gopkg.in/yaml.v3"
)

const DefaultPath = ".sentinelflow/baseline.yaml"

// File represents a baseline file
type File struct {
	Version  string    `yaml:"version"`
	Findings []Entry   `yaml:"findings"`
}

// Entry represents a baselined finding
type Entry struct {
	ID     string `yaml:"id,omitempty"`
	File   string `yaml:"file,omitempty"`
	RuleID string `yaml:"rule_id,omitempty"`
	Hash   string `yaml:"hash,omitempty"`
	Reason string `yaml:"reason,omitempty"`
}

// Load reads a baseline file from disk
func Load(path string) (*File, error) {
	if path == "" {
		path = DefaultPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Version: "1.0", Findings: []Entry{}}, nil
		}
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
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

// Generate creates a baseline from scan findings
func Generate(findings []api.Finding) *File {
	entries := make([]Entry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, Entry{
			ID:     f.ID,
			File:   f.Location.File,
			RuleID: f.RuleID,
			Hash:   HashFinding(f),
		})
	}
	return &File{Version: "1.0", Findings: entries}
}

// HashFinding creates a stable hash for a finding
func HashFinding(f api.Finding) string {
	key := fmt.Sprintf("%s|%s|%s|%d", f.RuleID, f.Location.File, f.Title, f.Location.StartLine)
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:8])
}

// Filter removes baselined findings from the result set
func Filter(findings []api.Finding, baseline *File) []api.Finding {
	if baseline == nil || len(baseline.Findings) == 0 {
		return findings
	}

	baselined := make(map[string]bool)
	for _, e := range baseline.Findings {
		if e.Hash != "" {
			baselined[e.Hash] = true
		}
		if e.ID != "" {
			baselined["id:"+e.ID] = true
		}
		// Legacy entries without ID/hash: suppress by rule+file only. When ID or
		// hash is present, rule:file must not blanket-suppress new findings in
		// the same file (false green for same-rule new secrets/IaC).
		if e.ID == "" && e.Hash == "" && e.RuleID != "" && e.File != "" {
			baselined[fmt.Sprintf("%s:%s", e.RuleID, e.File)] = true
		}
	}

	var filtered []api.Finding
	for _, f := range findings {
		if baselined[HashFinding(f)] {
			continue
		}
		if f.ID != "" && baselined["id:"+f.ID] {
			continue
		}
		if baselined[fmt.Sprintf("%s:%s", f.RuleID, f.Location.File)] {
			continue
		}
		filtered = append(filtered, f)
	}

	return filtered
}

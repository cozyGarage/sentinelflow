// Package api defines the public API types for SentinelFlow
package api

import (
	"encoding/json"
	"strings"
	"time"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ParseSeverity converts a severity string into a Severity value.
// Unknown values map to SeverityInfo.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "unknown", "":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// Rank returns a comparable severity rank (critical highest).
func (s Severity) Rank() int {
	switch ParseSeverity(string(s)) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// MeetsMinimum reports whether found is at least as severe as minimum.
func MeetsMinimum(found Severity, minimum string) bool {
	min := ParseSeverity(minimum)
	if minimum == "" {
		min = SeverityMedium
	}
	return found.Rank() >= min.Rank()
}

// FindingType represents the category of a security finding
type FindingType string

const (
	FindingTypeSecret           FindingType = "secret"
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypePolicyViolation  FindingType = "policy_violation"
	FindingTypeInsecureCode     FindingType = "insecure_code"
)

// Location represents where a finding was discovered
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	StartCol  int    `json:"start_col,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// Finding represents a single security issue discovered during scanning
type Finding struct {
	ID          string         `json:"id"`
	Type        FindingType    `json:"type"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Location    Location       `json:"location"`
	Remediation string         `json:"remediation,omitempty"`
	References  []string       `json:"references,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	RuleID      string         `json:"rule_id,omitempty"`
	Scanner     string         `json:"scanner"`
	Confidence  float64        `json:"confidence,omitempty"`
	CVE         string         `json:"cve,omitempty"`
	CVSS        float64        `json:"cvss,omitempty"`
	CWE         []string       `json:"cwe,omitempty"`
}

// DurationMS is a time.Duration that JSON-encodes as milliseconds.
type DurationMS time.Duration

// MarshalJSON encodes the duration as an integer number of milliseconds.
func (d DurationMS) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).Milliseconds())
}

// UnmarshalJSON decodes milliseconds into a duration.
func (d *DurationMS) UnmarshalJSON(data []byte) error {
	var ms int64
	if err := json.Unmarshal(data, &ms); err != nil {
		return err
	}
	*d = DurationMS(time.Duration(ms) * time.Millisecond)
	return nil
}

// Std returns the underlying time.Duration.
func (d DurationMS) Std() time.Duration {
	return time.Duration(d)
}

// ScanResult contains the complete results of a security scan
type ScanResult struct {
	Findings    []Finding     `json:"findings"`
	ScannerRuns []ScannerRun  `json:"scanner_runs"`
	Metadata    ScanMetadata  `json:"metadata"`
	Duration    DurationMS    `json:"duration_ms"`
}

// ScannerRun contains information about an individual scanner execution
type ScannerRun struct {
	Scanner       string     `json:"scanner"`
	StartTime     time.Time  `json:"start_time"`
	EndTime       time.Time  `json:"end_time"`
	Duration      DurationMS `json:"duration_ms"`
	FilesCount    int        `json:"files_count"`
	FindingsCount int        `json:"findings_count"`
	Error         string     `json:"error,omitempty"`
	// Warnings are non-fatal signals (e.g. skipped oversized files). They must
	// not fail CI by themselves — use Error for hard failures.
	Warnings []string `json:"warnings,omitempty"`
}

// ScanMetadata contains information about the scan environment
type ScanMetadata struct {
	TargetPath          string    `json:"target_path"`
	StartTime           time.Time `json:"start_time"`
	EndTime             time.Time `json:"end_time"`
	SentinelFlowVersion string    `json:"sentinelflow_version"`
	GitCommit           string    `json:"git_commit,omitempty"`
	GitBranch           string    `json:"git_branch,omitempty"`
}

// CountBySeverity returns a map of severity to count
func (r *ScanResult) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// FilterBySeverity returns findings matching the given severity
func (r *ScanResult) FilterBySeverity(severity Severity) []Finding {
	var filtered []Finding
	for _, f := range r.Findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

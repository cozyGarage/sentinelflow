// Package api defines the public API types for SentinelFlow
package api

import (
	"encoding/json"
	"fmt"
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
	FindingTypeHardening        FindingType = "hardening"
	FindingTypeMalware          FindingType = "malware"
	FindingTypeComponent        FindingType = "component"
)

// Location represents where a finding was discovered
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	StartCol  int    `json:"start_col,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
	// ArtifactPath is a nested member path (archive!/inner!/file) when the
	// finding lives inside a binary or archive rather than a source file.
	ArtifactPath string `json:"artifact_path,omitempty"`
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
	// EPSS is the FIRST.org probability (0-1) that the CVE is exploited in the next 30 days.
	EPSS float64 `json:"epss,omitempty"`
	// KEV is true when the CVE is in the CISA Known Exploited Vulnerabilities catalog.
	KEV bool `json:"kev,omitempty"`
	// Reachable is set by qualified reachability analysis (govulncheck for Go):
	// true for an observed call path, false only when a completed supported scan
	// establishes non-reachability, and nil when analysis is missing or unknown.
	Reachable *bool    `json:"reachable,omitempty"`
	CWE       []string `json:"cwe,omitempty"`
	OWASP     []string `json:"owasp,omitempty"`
	// Fingerprint is a line-independent identity (rule + path + snippet/value
	// hash). Used by baseline v2 and SARIF partialFingerprints.
	Fingerprint string `json:"fingerprint,omitempty"`
	// ValueHash is a hex digest of a secret/component value used for
	// fingerprints without persisting the raw secret.
	ValueHash string `json:"value_hash,omitempty"`
}

// SkippedFile records a path the engine declined to scan.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
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

// BaselineSummary counts findings before and after baseline filtering.
// Total is the pre-filter count. New is the post-filter count the fail gate uses.
type BaselineSummary struct {
	Enabled     bool `json:"enabled"`
	Total       int  `json:"total"`
	Suppressed  int  `json:"suppressed"`
	New         int  `json:"new"`
	Inline      int  `json:"inline,omitempty"`
	VEX         int  `json:"vex,omitempty"`
	Diff        int  `json:"diff,omitempty"`
	BaselineRef int  `json:"baseline_ref,omitempty"`
}

// SuppressedObservation is a redacted audit record. It carries only a stable
// finding fingerprint and policy metadata, never the original snippet/value.
type SuppressedObservation struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id,omitempty"`
	Source      string `json:"source"`
	Reason      string `json:"reason"`
	Authority   string `json:"authority"`
}

// ScanResult contains the complete results of a security scan
type ScanResult struct {
	Findings    []Finding    `json:"findings"`
	ScannerRuns []ScannerRun `json:"scanner_runs"`
	// Status summarizes analysis coverage. It is additive; empty means a legacy producer.
	Status     ScanStatus              `json:"status,omitempty"`
	Metadata   ScanMetadata            `json:"metadata"`
	Duration   DurationMS              `json:"duration_ms"`
	Baseline   *BaselineSummary        `json:"baseline,omitempty"`
	Suppressed []SuppressedObservation `json:"suppressed,omitempty"`
	Skipped    []SkippedFile           `json:"skipped,omitempty"`
}

// ScannerRun contains information about an individual scanner execution
type ScannerRun struct {
	Scanner string `json:"scanner"`
	// Status distinguishes a clean empty result from analysis that did not complete.
	Status        ScanStatus `json:"status,omitempty"`
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

// ScanStatus is the execution and coverage outcome for a scan or scanner.
type ScanStatus string

const (
	ScanStatusComplete      ScanStatus = "complete"
	ScanStatusPartial       ScanStatus = "partial"
	ScanStatusFailed        ScanStatus = "failed"
	ScanStatusTimedOut      ScanStatus = "timed-out"
	ScanStatusNotApplicable ScanStatus = "not-applicable"
	ScanStatusSkipped       ScanStatus = "skipped"
)

// ScanMetadata contains information about the scan environment
type ScanMetadata struct {
	TargetPath          string                    `json:"target_path"`
	StartTime           time.Time                 `json:"start_time"`
	EndTime             time.Time                 `json:"end_time"`
	SentinelFlowVersion string                    `json:"sentinelflow_version"`
	GitCommit           string                    `json:"git_commit,omitempty"`
	GitBranch           string                    `json:"git_branch,omitempty"`
	VulnerabilityData   []VulnerabilityDataSource `json:"vulnerability_data,omitempty"`
}

// VulnerabilityDataSource identifies the advisory evidence used by a scan.
// SnapshotID and AcquiredAt are empty for live sources that expose no snapshot.
type VulnerabilityDataSource struct {
	Source     string     `json:"source"`
	Mode       string     `json:"mode"`
	Ecosystem  string     `json:"ecosystem"`
	SnapshotID string     `json:"snapshot_id,omitempty"`
	AcquiredAt *time.Time `json:"acquired_at,omitempty"`
	Supported  bool       `json:"supported"`
	Status     string     `json:"status"`
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

// RiskLabel summarises EPSS and KEV for display, e.g. "CISA KEV, EPSS 94.1%".
func RiskLabel(f Finding) string {
	var parts []string
	if f.KEV {
		parts = append(parts, "CISA KEV (exploited in the wild)")
	}
	if f.EPSS > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.1f%%", f.EPSS*100))
	}
	if f.Reachable != nil {
		if *f.Reachable {
			parts = append(parts, "vulnerable code is called")
		} else {
			parts = append(parts, "vulnerable code is not called")
		}
	}
	return strings.Join(parts, ", ")
}

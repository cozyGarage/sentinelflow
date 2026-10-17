package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseSeverityAndRank(t *testing.T) {
	if ParseSeverity("CRITICAL") != SeverityCritical {
		t.Fatal("CRITICAL")
	}
	if ParseSeverity("moderate") != SeverityMedium {
		t.Fatal("moderate")
	}
	if !MeetsMinimum(SeverityHigh, "medium") {
		t.Fatal("high should meet medium")
	}
	if MeetsMinimum(SeverityLow, "high") {
		t.Fatal("low should not meet high")
	}
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Fatal("critical should outrank high")
	}
}

func TestDurationMSJSON(t *testing.T) {
	result := ScanResult{
		Findings: []Finding{},
		Duration: DurationMS(1500 * time.Millisecond),
		ScannerRuns: []ScannerRun{
			{Scanner: "secrets", Duration: DurationMS(250 * time.Millisecond)},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["duration_ms"]) != "1500" {
		t.Fatalf("expected duration_ms=1500, got %s", string(raw["duration_ms"]))
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Duration.Std() != 1500*time.Millisecond {
		t.Fatalf("round-trip duration = %v", decoded.Duration.Std())
	}
}

func TestScanStatusJSONIsAdditiveAndDistinguishesCleanFromSkipped(t *testing.T) {
	legacy := `{"findings":[],"scanner_runs":[{"scanner":"secrets","findings_count":0}]}`
	var old ScanResult
	if err := json.Unmarshal([]byte(legacy), &old); err != nil {
		t.Fatal(err)
	}
	if old.Status != "" || old.ScannerRuns[0].Status != "" {
		t.Fatalf("legacy documents must decode without invented execution claims: %+v", old)
	}

	clean := ScanResult{Status: ScanStatusComplete, ScannerRuns: []ScannerRun{{Scanner: "secrets", Status: ScanStatusComplete}}}
	skipped := ScanResult{Status: ScanStatusSkipped}
	cleanJSON, err := json.Marshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	skippedJSON, err := json.Marshal(skipped)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cleanJSON), `"status":"complete"`) || !strings.Contains(string(skippedJSON), `"status":"skipped"`) {
		t.Fatalf("explicit outcomes missing: clean=%s skipped=%s", cleanJSON, skippedJSON)
	}
}

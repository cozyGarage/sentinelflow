package vulndb

import "testing"

func TestParseCVSSBaseScoreCriticalVector(t *testing.T) {
	score := parseCVSSBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if score < 9.0 {
		t.Fatalf("expected critical-ish score >= 9, got %v", score)
	}
	if got := cvssToSeverity(score); got != "critical" {
		t.Fatalf("expected critical, got %s", got)
	}
}

func TestParseCVSSBaseScoreHighVector(t *testing.T) {
	score := parseCVSSBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
	if score < 7.0 {
		t.Fatalf("expected high-ish score >= 7, got %v", score)
	}
	if got := cvssToSeverity(score); got != "high" {
		t.Fatalf("expected high, got %s", got)
	}
}

func TestParseCVSSBaseScoreNonVector(t *testing.T) {
	if score := parseCVSSBaseScore("not-a-vector"); score != 0 {
		t.Fatalf("expected 0, got %v", score)
	}
}

func TestNormalizeOSVSeverity(t *testing.T) {
	if got := normalizeOSVSeverity("CRITICAL"); got != "critical" {
		t.Fatalf("got %s", got)
	}
	if got := normalizeOSVSeverity("Moderate"); got != "medium" {
		t.Fatalf("got %s", got)
	}
	if got := normalizeOSVSeverity(""); got != "" {
		t.Fatalf("got %s", got)
	}
}

func TestSC074_OSVAliasesSurviveNormalization(t *testing.T) {
	osv := OSVVulnerability{ID: "OSV-1", Aliases: []string{"GHSA-aaaa", "CVE-2024-0001"}}
	got := osv.toVulnerability("lodash", "npm")
	if len(got.Aliases) != 2 || got.Aliases[0] != "GHSA-aaaa" || got.Aliases[1] != "CVE-2024-0001" {
		t.Fatalf("aliases lost during OSV normalization: %+v", got)
	}
	got.Aliases[0] = "mutated"
	if osv.Aliases[0] != "GHSA-aaaa" {
		t.Fatal("normalized aliases must not mutate the source record")
	}
}

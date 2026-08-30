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

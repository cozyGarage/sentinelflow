package vulndb

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/mod/semver"
)

// compareVersions orders versions only where the selected range semantics are
// qualified. SEMVER uses Go's semver implementation. ECOSYSTEM currently
// supports numeric dotted releases for the explicitly supported ecosystems;
// qualifier-bearing forms remain uncertain until their native ordering is
// implemented, and therefore fail closed instead of producing a clean result.
func compareVersions(rangeType, ecosystem, a, b string) (int, error) {
	if rangeType == "SEMVER" {
		va, vb := "v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v")
		if !semver.IsValid(va) || !semver.IsValid(vb) {
			return 0, fmt.Errorf("unsupported SEMVER ordering for %s versions %q and %q", ecosystem, a, b)
		}
		return semver.Compare(va, vb), nil
	}
	if rangeType != "ECOSYSTEM" {
		return 0, fmt.Errorf("unsupported OSV range type %q for %s", rangeType, ecosystem)
	}
	if !ecosystemSupported(ecosystem) || !numericDottedVersion(a) || !numericDottedVersion(b) {
		return 0, fmt.Errorf("unsupported ECOSYSTEM ordering for %s versions %q and %q", ecosystem, a, b)
	}
	return compareSegments(a, b), nil
}

func numericDottedVersion(v string) bool {
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return false
	}
	for _, r := range v {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return !strings.HasPrefix(v, ".") && !strings.HasSuffix(v, ".") && !strings.Contains(v, "..")
}

// compareSegments compares numeric dotted components without integer overflow.
func compareSegments(a, b string) int {
	sa, sb := segments(strings.TrimPrefix(a, "v")), segments(strings.TrimPrefix(b, "v"))
	for i := 0; i < len(sa) || i < len(sb); i++ {
		switch {
		case i >= len(sa):
			return -segmentSign(sb[i])
		case i >= len(sb):
			return segmentSign(sa[i])
		}
		x, y := sa[i], sb[i]
		nx, ex := decimalValue(x)
		ny, ey := decimalValue(y)
		switch {
		case ex && ey:
			if c := compareDecimal(nx, ny); c != 0 {
				return c
			}
		case ex: // number beats letters (release > pre-release)
			return 1
		case ey:
			return -1
		default:
			if c := strings.Compare(strings.ToLower(x), strings.ToLower(y)); c != 0 {
				return c
			}
		}
	}
	return 0
}

// segmentSign: an extra numeric segment makes a version newer (1.0.1 > 1.0),
// an extra letter segment makes it older (1.0rc1 < 1.0), zeros are neutral.
func segmentSign(seg string) int {
	if n, ok := decimalValue(seg); ok {
		if n == "" {
			return 0
		}
		return 1
	}
	return -1
}

func decimalValue(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return strings.TrimLeft(s, "0"), true
}

func compareDecimal(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func segments(v string) []string {
	v, _, _ = strings.Cut(v, "+") // build metadata never orders
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range v {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case len(cur) > 0 && unicode.IsDigit(r) != unicode.IsDigit(cur[len(cur)-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

// affects reports whether version is affected by one OSV "affected" entry.

func affects(rangeType, ecosystem string, events []rangeEvent, version string) (bool, error) {
	if _, err := compareVersions(rangeType, ecosystem, version, version); err != nil {
		return false, err
	}
	for _, event := range events {
		fields := 0
		for _, value := range []string{event.Introduced, event.Fixed, event.LastAffected, event.Limit} {
			if value != "" {
				fields++
			}
		}
		if fields != 1 {
			return false, fmt.Errorf("invalid OSV range event for %s: expected exactly one of introduced, fixed, last_affected, or limit", ecosystem)
		}
	}
	before, err := beforeLimits(rangeType, ecosystem, version, events)
	if err != nil || !before {
		return false, err
	}
	var timeline []rangeEvent
	for _, event := range events {
		if event.Limit == "" {
			timeline = append(timeline, event)
		}
	}
	var compareErr error
	sort.SliceStable(timeline, func(i, j int) bool {
		if compareErr != nil {
			return false
		}
		left, right := timeline[i].version(), timeline[j].version()
		if left == "" || right == "" {
			return left == "" && right != ""
		}
		cmp, err := compareVersions(rangeType, ecosystem, left, right)
		if err != nil {
			compareErr = err
			return false
		}
		return cmp < 0
	})
	if compareErr != nil {
		return false, compareErr
	}
	affected := false
	for _, e := range timeline {
		switch {
		case e.Introduced != "":
			cmp := 1
			if e.Introduced != "0" {
				var err error
				cmp, err = compareVersions(rangeType, ecosystem, version, e.Introduced)
				if err != nil {
					return false, err
				}
			}
			if e.Introduced == "0" || cmp >= 0 {
				affected = true
			}
		case e.Fixed != "":
			cmp, err := compareVersions(rangeType, ecosystem, version, e.Fixed)
			if err != nil {
				return false, err
			}
			if cmp >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			cmp, err := compareVersions(rangeType, ecosystem, version, e.LastAffected)
			if err != nil {
				return false, err
			}
			if cmp > 0 {
				affected = false
			}
		}
	}
	return affected, nil
}

func beforeLimits(rangeType, ecosystem, version string, events []rangeEvent) (bool, error) {
	found := false
	for _, event := range events {
		if event.Limit == "" {
			continue
		}
		found = true
		if strings.Contains(event.Limit, "*") {
			return true, nil
		}
		cmp, err := compareVersions(rangeType, ecosystem, version, event.Limit)
		if err != nil {
			return false, err
		}
		if cmp < 0 {
			return true, nil
		}
	}
	return !found, nil
}

type rangeEvent struct {
	Introduced, Fixed, LastAffected, Limit string
}

func (e rangeEvent) version() string {
	switch {
	case e.Introduced == "0":
		return "" // sorts first
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	}
	return e.LastAffected
}

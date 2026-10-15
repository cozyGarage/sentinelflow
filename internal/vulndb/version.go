package vulndb

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/mod/semver"
)

// compareVersions orders two versions for OSV range evaluation.
// SEMVER ranges use real semver (prerelease < release). ECOSYSTEM ranges use a
// segment-wise comparison that is right for numeric dotted versions in every
// supported ecosystem (Maven, PyPI, RubyGems, NuGet, Packagist).
// ponytail: no full PEP 440 / Maven ComparableVersion qualifier ordering
// (e.g. "1.0.post1", "1.0-sp1"); add per-ecosystem comparators if mismatches show up.
func compareVersions(rangeType, a, b string) int {
	if rangeType == "SEMVER" {
		va, vb := "v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v")
		if semver.IsValid(va) && semver.IsValid(vb) {
			return semver.Compare(va, vb)
		}
	}
	return compareSegments(a, b)
}

// compareSegments splits on non-alphanumerics and number/letter boundaries.
// Numbers compare numerically; a letter segment (pre-release such as "rc",
// "beta") sorts before the end of the version, so 1.0rc1 < 1.0 < 1.0.1.
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
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
		case ex == nil: // number beats letters (release > pre-release)
			return 1
		case ey == nil:
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
	if n, err := strconv.ParseUint(seg, 10, 64); err == nil {
		if n == 0 {
			return 0
		}
		return 1
	}
	return -1
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
func affects(rangeType string, events []rangeEvent, version string) bool {
	sort.SliceStable(events, func(i, j int) bool {
		return compareVersions(rangeType, events[i].version(), events[j].version()) < 0
	})
	affected := false
	for _, e := range events {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || compareVersions(rangeType, version, e.Introduced) >= 0 {
				affected = true
			}
		case e.Fixed != "":
			if compareVersions(rangeType, version, e.Fixed) >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if compareVersions(rangeType, version, e.LastAffected) > 0 {
				affected = false
			}
		}
	}
	return affected
}

type rangeEvent struct {
	Introduced, Fixed, LastAffected string
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

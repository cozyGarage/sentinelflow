# OSV interval boundaries

SC-085 pins the supported OSV interval semantics used by the offline vulnerability matcher. OSV checks exact `affected.versions` entries separately, then evaluates range events. For supported `SEMVER` and `ECOSYSTEM` comparisons, `introduced` is inclusive, `fixed` is exclusive, and `last_affected` is inclusive. A `limit` is a strict upper bound: versions at the limit are excluded. An absent limit is unbounded; `*` is treated as an infinite limit. Events are sorted by version before evaluation so source ordering does not change results.

The matcher validates that each event contains exactly one event field. Unsupported or malformed input remains an explicit evaluation error. GIT ranges continue to follow SC-084: exact listed versions can match, while an unlisted version is unassessed.

OSV `withdrawn` is an RFC3339 instant. An advisory remains usable before that instant and is ignored at or after it. Invalid timestamps are surfaced as errors instead of silently changing the result. Offline refresh uses its acquisition-time clock; later queries recheck withdrawal status, including for legacy indexes.

These boundaries follow the [OSV schema specification](https://ossf.github.io/osv-schema/), especially the range event and withdrawn field definitions. This is not a claim of complete native ordering for every ecosystem qualifier; SC-083 documents the comparator boundary.

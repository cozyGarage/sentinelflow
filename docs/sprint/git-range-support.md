# OSV GIT range support

SC-084 prevents offline advisory matching from treating an unsupported OSV `GIT` range as a clean package. The offline matcher cannot map repository commit intervals to the resolved package version, so it returns an explicit unassessed error containing the ecosystem and advisory ID. The dependency scanner retains that operational failure in its run outcome.

Exact OSV `versions` entries are checked first and remain authoritative exact matches. If an exact entry matches, the advisory is reported even when a GIT range is also present. If no listed version matches and a GIT range is present, the result is uncertain and the query errors; an absent GIT range with no match remains clean under the supported range types.

This does not resolve commit ancestry or qualify mapping package versions to source commits. A future implementation would need source identity, commit graph provenance and explicit supported range semantics before it can evaluate GIT intervals.

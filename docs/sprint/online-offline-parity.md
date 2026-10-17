# Online/offline advisory parity

SC-086 uses one pinned OSV fixture corpus as input to both the offline archive indexer and an HTTP fixture standing in for the OSV query API. The parity test sends identical ecosystem, package, and version tuples through both paths, then compares sorted advisory IDs and stable consumer-facing vulnerability fields.

The tuple matrix includes no-match, introduced-range boundary, in-range, fixed boundary, and an exact listed-version match. The test does not contact `api.osv.dev`; the mock API's responses are pinned to the expected match set, while the offline path independently evaluates the same raw advisory records.

Parity is asserted only for supported semantics. Unsupported comparator qualifiers and GIT ranges remain explicit errors under SC-083 and SC-084, rather than being folded into a clean-result parity claim.

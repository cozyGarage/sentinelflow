# Risk enrichment completeness

SC-089 distinguishes optional EPSS/KEV enrichment from the required `fail_on.kev` policy. Ordinary `risk_enrichment` failures remain visible as a partial scanner run with a warning. When `fail_on.kev` is enabled, enrichment runs even if optional risk enrichment is otherwise disabled. If a CVE finding exists and KEV data is unavailable, the run fails closed. Offline mode cannot satisfy a required KEV decision and reports that failure; no CVE findings means no KEV lookup is needed.

EPSS responses are complete only when each requested CVE has a parseable finite score in the inclusive range 0 to 1. Missing, malformed, or out-of-range values return an EPSS completeness error while preserving valid scores and KEV membership already fetched. An EPSS-only failure does not fail a required KEV gate when the KEV catalog was successfully evaluated.

This slice exposes availability and completeness errors; it does not yet attach per-finding risk-source timestamps or immutable catalog versions. Offline mode intentionally skips optional risk enrichment.

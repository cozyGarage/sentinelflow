# Batch query partial results

SC-088 preserves successful querybatch chunks and fully fetched advisory details when a later chunk is cancelled or a sibling detail fetch fails. The single-query multi-source path also retains positive results when any source reports an error, while returning an error that marks the lookup incomplete. Query results remain position-aligned to the original package queries. Callers can retain safe positive matches while still treating the scan as operationally incomplete.

Only complete package answers are cached. Missing detail records are omitted from the partial finding list rather than treating abbreviated querybatch stubs as full advisories. A response whose result count does not align with its request chunk is rejected without guessing which package each result belongs to.

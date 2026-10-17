# Suppression audit acceptance

Scope: SC-076–SC-080. Implementation and hosted evidence are being recorded on the branch for this slice; checks are pending until its final PR head exists.

## Local evidence

- Suppressed observations retain only stable fingerprints and source/reason/authority metadata; scan summaries reconcile total, suppressed, new, and source subtotals.
- Inline ignore tests cover comment-only recognition, strict reason/wildcard rejection with legacy compatibility, path traversal, absolute paths and symlink escape.
- Fingerprint regressions cover delimiter ambiguity and dependency ecosystem/package/version identity.
- Configuration tests cover strict-mode opt-in. Full `go test ./...` and `go test -race -count=1 ./...` passed; `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint-doc checker with its four positive/negative tests, and all eleven SC-076–SC-080 selector rows (13 executed test cases including subtests) passed locally. A hermeticity fix ensures the Git metadata env-fallback test does not accidentally inspect the surrounding checkout.

## Hosted evidence

Hosted evidence for implementation head `c7d26c0408a885d05118036981cca31b0f9e5c54`: [CI, including the complete scan-correctness matrix and SC-076–SC-080 selectors](https://github.com/cozyGarage/sentinelflow/actions/runs/39053922567) and [Security Scan](https://github.com/cozyGarage/sentinelflow/actions/runs/39053922597) completed successfully. `gh pr checks 59` reported 71 passed and zero failed checks. These checks cover the implementation commit; the acceptance-record update will receive a fresh exact-head run before merge.

## Limits

Repository provenance is not independent approval. Public suppression records contain no source paths, snippets, or raw values. Fingerprint changes may expose findings previously matched by old v2 fingerprints; review and update intended baseline entries individually.

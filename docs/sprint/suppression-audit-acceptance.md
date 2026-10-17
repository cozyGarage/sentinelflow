# Suppression audit acceptance

Scope: SC-076–SC-080. Implementation and hosted evidence are being recorded on the branch for this slice; checks are pending until its final PR head exists.

## Local evidence

- Suppressed observations retain only stable fingerprints and source/reason/authority metadata; scan summaries reconcile total, suppressed, new, and source subtotals.
- Inline ignore tests cover comment-only recognition, strict reason/wildcard rejection with legacy compatibility, path traversal, absolute paths and symlink escape.
- Fingerprint regressions cover delimiter ambiguity and dependency ecosystem/package/version identity.
- Configuration tests cover strict-mode opt-in. Full `go test ./...` and `go test -race -count=1 ./...` passed; `go vet ./...`, `actionlint .github/workflows/ci.yml`, sprint-doc checker with its four positive/negative tests, and all eleven SC-076–SC-080 selector rows (13 executed test cases including subtests) passed locally. A hermeticity fix ensures the Git metadata env-fallback test does not accidentally inspect the surrounding checkout.

## Hosted evidence

Pending PR and final-head GitHub Actions / Security Scan results. Record the exact commit and run links here before merge.

## Limits

Repository provenance is not independent approval. Public suppression records contain no source paths, snippets, or raw values. Fingerprint changes may expose findings previously matched by old v2 fingerprints; review and update intended baseline entries individually.

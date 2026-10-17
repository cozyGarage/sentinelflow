# Scan outcome follow-up acceptance

This is the evidence record for follow-up items SC-004–SC-006. It is not a claim of organizational readiness. The stable 32-item core acceptance table remains in [scan-correctness-acceptance.md](scan-correctness-acceptance.md).

## Implemented contract

- `ScanResult.status` and `ScannerRun.status` are optional JSON strings with `complete`, `partial`, `failed`, `timed-out`, `not-applicable`, and `skipped` values. Missing values remain unknown for legacy consumers; zero findings alone does not imply success.
- Engine status is derived from scanner execution, warnings, errors and cancellation. Auto-mode missing external tools are explicitly skipped; required missing tools fail. A clean empty scan and a scan with no configured scanners have distinct aggregate outcomes.
- VEX, diff and baseline-load failures return the findings already collected and add a failing `postprocess:<stage>` run. The CLI writes the partial report before returning an operational failure. Report target paths and diagnostics are redacted.
- Dependency `fail_on_error: false` can soften the CLI exit, but it does not rewrite the scanner's failed status. Required reachability errors remain fatal.
- An aggregate `skipped` result fails the CLI gate with “no scanners executed”; an accidentally empty scanner configuration cannot exit successfully.
- Text, Markdown and JSON report formats expose outcome status. Empty findings with a degraded result no longer produce the green “No security issues found” CLI summary.

## Failure retention table

| Stage | Findings available | Report output | Required failure behavior |
| --- | --- | --- | --- |
| Scanner execution | Partial findings survive with scanner run status/error. | CLI emits report if engine returns a result. | Required failure exits operationally; optional dependency errors may be softened only by explicit config. |
| VEX/diff/baseline processing | Findings collected before the failing stage survive. | CLI attempts the configured report, then exits operationally. | Aggregate status is `failed`; stage is named in `scanner_runs`. |
| Report formatting | Result exists in memory, but requested output is unavailable. | No usable report. | CLI exits operationally. |
| Report file write | Result and formatted data exist, but requested file is absent/incomplete. | No persisted report at the requested path. | CLI exits operationally. |
| Collection before result construction | No safe `ScanResult` exists. | No report. | CLI returns top-level error/timeout. |

## Local validation

The full `go test ./...` suite passed after the final outcome reducer change. The full race suite passed before that final reducer-only adjustment; targeted scanner/CLI race checks are rerun for the final source. Added regressions cover legacy JSON decoding, clean-zero versus skipped outcomes, partial findings with scanner errors, VEX/diff/baseline failure retention, auto/required missing tools, and non-strict dependency error visibility. The six SC-004–SC-006 selector invocations passed with the repository's zero-match guard. `go vet ./...`, `scripts/check-scan-sprint-docs.py`, `scripts/test_scan_sprint_docs.py`, `actionlint .github/workflows/ci.yml`, and `git diff --check` passed. The live self-scan reported zero unsuppressed findings, two inline suppressions for fixed executable calls, and a partial dependency inventory warning because only `go.mod` requirements are used; no clean-coverage claim is made. CI now has named selector rows for SC-004, SC-005 and SC-006. Hosted status is pending until Actions runs on the final pushed PR head.

## Remaining limits

`not-applicable` is part of the public enum but is reserved until a producer can prove applicability. Individually disabled scanners are still omitted from `scanner_runs`; when no scanner runs, only the aggregate `skipped` result is available. Coverage accounting for unsupported/excluded file classes remains in SC-065/SC-066. Legacy consumers must not assume an absent status is complete. Hosted Actions and Security Scan are not yet evidence for this work until their exact-head runs finish.

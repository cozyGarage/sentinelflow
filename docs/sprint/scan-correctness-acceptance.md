# Scan-correctness acceptance report

**Status: INCOMPLETE — local implementation plus CI-coverage follow-up.** This branch includes dedicated SC-001 and SC-100 Actions checks and a core-evidence reconciler; these additions pass local checks. Hosted Actions and some real-tool evidence remain outstanding.

Prepared 2026-10-17. Repository: `/home/trung/Projects/sentinelflow`. Checked-out branch: `codex/scan-correctness-sprint`. Base HEAD: `cdd7cd7c390c65809fcd08e10dd0492360579565`. Previously validated implementation source: `3e128766b4e497136984bb0f9fbcafe9d91e7693`. The branch includes follow-up documentation and Actions coverage changes; no PR exists and GitHub Actions has not run on the branch.

## Core item status

`Local evidence` means a focused deterministic check passed in this implementation worktree. It does not close the item until all acceptance conditions and exact-revision hosted evidence are met.

| ID | Status | Current evidence / remaining work |
| --- | --- | --- |
| SC-001 | Local baseline; named Actions check added | Base, implementation revision, Go 1.27.2, and cache/temp paths recorded. New hosted check records exact checkout and toolchain; local job-equivalent and hosted evidence pending. |
| SC-002 | Local evidence | Fake tools cover findings then failure, truncation, clean completion, cancellation, args, baseline failures and cleanup; hosted selection pending. |
| SC-003 | Local evidence | Inventory, identity, unknown, comparison and exit decisions are written in the plan/compatibility notes; hosted regression pending. |
| SC-011 | Local evidence | Stale checksum version and captured OSV query tuple regressions pass. |
| SC-012 | Local evidence | Inline/grouped/commented Go `require`, location and malformed syntax regressions pass. |
| SC-013 | Local evidence | Missing/malformed `go.sum` preserves declared requirements. |
| SC-014 | Local evidence | Workspace/replacement limitation warning verified. Full selected-graph resolution remains outside scope and is not claimed. |
| SC-021 | Local evidence | npm v2/v3 retains multiple installed versions; end-to-end OSV test queries each instance. |
| SC-022 | Local evidence | Deterministic ordering test passes. |
| SC-023 | Local evidence | Recursive npm v1 nested dependency test passes. |
| SC-024 | Local evidence | Query, finding, JSON report and baseline tests preserve install identity; v2 weak-hash false suppression fixed. |
| SC-031 | Local evidence | Structured-output requirement, result collection/envelope checks and Gitleaks exit-code argument are covered; real external-adapter binaries remain unqualified. |
| SC-032 | Local evidence | Required fake emits a finding then exits operationally; finding and error survive. |
| SC-033 | Local evidence | Empty, malformed and truncated required reports fail; Gitleaks wrong root and missing Semgrep/Grype/Syft/Trivy report identity or collections fail while explicit empty reports remain valid. |
| SC-034 | Local evidence | Auto-mode process/report failures retain any parsed findings and become warnings; required fake Gitleaks failure reaches built CLI and exits `2`. |
| SC-041 | Local evidence | Govulncheck finding followed by nonzero exit remains operational failure; positive evidence survives. |
| SC-042 | Local evidence | Clean, malformed, truncated and cancelled stream cases pass. |
| SC-043 | Local evidence | Exact advisory/module/version matching, alias and symbol-level requirements tested. Pinned govulncheck v1.9.0 was exercised against local synthetic DB/module fixtures: called symbol is reachable; imported-only and absent observations stay unknown; a missing `go.mod` produces an error and remains unknown. Hosted qualification pending. |
| SC-044 | Local evidence | Unknown/reachable gates fail closed; required error is not softened; partial head finding is retained. |
| SC-051 | Local evidence | Head/base asymmetric fake failures reject comparison; scanner run error can coexist with nil engine error. |
| SC-052 | Local evidence | Missing/failed/mismatched outcomes rejected; complete comparable scan retains line-motion behavior. |
| SC-053 | Local evidence | Fresh scanner instances and scanner set comparability tested. |
| SC-054 | Local evidence | Cancellation cleanup, injected cleanup error, invalid ref, caller checkout state and successful cleanup tested. |
| SC-091 | Local evidence | Built CLI checks clean `0`, finding `1`, operational `2`, deadline `3`, report and partial-result behavior. |
| SC-092 | Local evidence | Built CLI times out after parseable tool output, writes partial report and returns `3`. |
| SC-093 | Local evidence | Threshold plus incomplete baseline exits `2`; unknown reachability plus failed base scan retains risk. |
| SC-094 | Configured; all local selectors and integration passed | `actionlint` passes; all 37 selector rows parsed from the current workflow matrix ran and matched tests through the zero-match guard; a deliberately nonexistent selector fails; tagged suite passed locally. Hosted CI pending. |
| SC-095 | Partial real-tool qualification | Pinned govulncheck v1.9.0 passes local reachable/imported-only/absent and missing-module operational cases against synthetic inputs. Local PATH inventory found Semgrep, Gitleaks, Grype, Syft, Trivy and YARA missing; these remain unqualified. Hosted SC-095 pending. |
| SC-097 | Local documentation | Go/npm, baseline/fingerprint, adapter, reachability and exit compatibility notes written; final code review and hosted checks pending. |
| SC-098 | Local evidence | Failing-first tests showed diagnostic leakage in engine and text/JSON/SARIF output, including a pre-result VEX load error leaking a marker from the target path through CLI stderr. Engine, reporter, and top-level CLI scan errors now redact it; built-CLI marker checks pass. |
| SC-099 | In progress | Local implementation revision and integrated gate results are recorded; hosted exact-commit Actions, PR link, and final acceptance remain absent. |
| SC-100 | Draft and reconciliation check added | [Proposed next assignment](next-assignment.md) orders follow-up risks. `scripts/check-scan-sprint-docs.py` verifies all 32 core IDs have backlog rows, acceptance rows and named Actions coverage; local positive/negative controls pass. Hosted evidence and final reconciliation remain. |

## Commands observed locally

Commands below were rerun against implementation commit `3e128766b4e497136984bb0f9fbcafe9d91e7693`, using Go cache under `/home/trung/.cache`; temp files used `/home/trung/.cache/tmp` to keep them outside the Git worktree and avoid `/tmp` quota.

| Command | Result |
| --- | --- |
| Focused Go inventory regressions `go test ./internal/scanner/dependencies -run 'Test(SC01[1-4])'` | Pass after correcting fixture version normalization and valid module major version. |
| External adapter contracts `go test ./internal/adapter/external -run 'TestSC03[1234]|TestParse(Semgrep|Gitleaks|TrivyFS)' -count=1` | Pass, including missing result collections, empty report controls, Semgrep-reported parse errors, and retained findings under auto warnings. |
| npm identity/report/baseline regression `go test ./internal/scanner/dependencies -run '^TestSC024_NpmInstancesReachOSVAndSurviveReportBaseline$'` | Pass. |
| Baseline-ref regressions `go test ./internal/scanner -run 'Test(SC05[1-4]|BaselineRef)'` | Pass. |
| Built CLI exit/report regression `go test ./internal/cli -run '^TestSC091_BuiltCLIExitAndPartialReport$'` | Pass for clean, threshold, comparison failure, required tool failure and timeout cases. |
| Diagnostic redaction `go test ./internal/reporter ./internal/scanner -run '^TestSC098_'` | Pass. |
| `go test -race -count=1 ./...` | Pass after the pre-result CLI redaction regression, tool-specific report validation and optional partial-report warning changes. |
| `go vet ./...` | Pass. |
| `go test -tags=integration -count=1 ./test/...` | Pass on current worktree; this test path may contact advisory services and is not a deterministic mock-only suite. Hosted job pending. |
| `bash scripts/install_checksum_test.sh`; `bash scripts/pr_comment_test.sh` | Both pass on current worktree. |
| `actionlint .github/workflows/ci.yml`; YAML parse; `git diff --check` | Pass after the current matrix and job additions. |
| `bash scripts/qualify-govulncheck.sh` | Pass locally against pinned govulncheck v1.9.0 and local synthetic module/DB fixtures; called=true, imported-only=unknown, absent=unknown, missing `go.mod`=operational error with unknown reachability. |
| `bash scripts/run-go-test-selector.sh ./internal/scanner/dependencies 'TestSC043_(GovulncheckNegativeRequiresQualifiedPackageObservation|NonSymbolScanCannotEstablishUnreachable)'` | Pass; both named tests were observed in JSON test events. A deliberately nonexistent selector failed with `no tests matched`, confirming green-with-no-tests is rejected. |
| Current `.github/workflows/ci.yml` `scan-correctness` matrix via `scripts/run-go-test-selector.sh` | Pass, 37 of 37 configured selector rows executed at least one passing test on the current source. The final rerun used `/home/trung/.cache/tmp` and loopback-enabled execution because `/tmp` quota and the default sandbox blocked temp writes and `httptest` listeners. This local selection audit does not replace hosted Actions. |
| `python3 scripts/check-scan-sprint-docs.py` plus missing-SC-001 negative control | Pass: all 32 core IDs have backlog, acceptance and named Actions entries; removing SC-001 from a temporary acceptance fixture is rejected. |
| Built CLI `TestSC091_BuiltCLIExitAndPartialReport/pre-result_engine_error_redacts_sensitive_target_path` | Failing-first: missing VEX file exposed `api_key=SENTINELFLOW_SECRET_MARKER` on stderr. After redacting top-level engine errors, the CLI returns exit `2`, omits the marker, and retains a useful redacted `load VEX` reason. |
| `test -z "$(gofmt -l .)"` | Pass after formatting the Go fixture modules. |

The Go race suite, vet, tagged integration suite, pinned govulncheck fixture and all 37 test selectors passed against implementation source commit `3e128766b4e497136984bb0f9fbcafe9d91e7693`. This follow-up adds named SC-001 and SC-100 jobs, the documentation reconciler, and README/acceptance updates; `actionlint`, the 32-ID positive check, and a missing-ID negative control pass on those current changes. No Go source changed after the cited implementation commit. No claim is made about hosted Actions.

## Hosted and upstream-tool evidence

- Hosted Actions: **not run**. The local commit has not been pushed. No PR exists. Do not infer a hosted result from local checks.
- Real tools: **partially qualified**. Pinned govulncheck v1.9.0 passed the synthetic local fixture qualification; Semgrep, Gitleaks, Grype, Syft, Trivy and YARA remain unqualified. See [real-tool-qualification.md](real-tool-qualification.md). Fake executable tests validate SentinelFlow behavior only.
- Integration tests: one local tagged run passed; it does not replace the final exact-head run or hosted job.

## Public behavior and remaining risks

Compatibility changes and limitations are recorded in [compatibility.md](compatibility.md). Go requirements are not represented as a fully selected graph. npm finding IDs distinguish installation paths. Modern baseline fingerprints no longer fall back to weak line-sensitive hashes. Partial reports accompany nonzero operational/deadline outcomes. Scanner diagnostics are redacted in engine outcomes and reports.

The sprint is incomplete until every selected core acceptance condition is reviewed, final repository-wide race/vet/helper/integration checks pass on a committed exact revision, workflow selectors pass on the exact final changes, the named hosted jobs pass, and SC-100's proposed assignment is reconciled against the final findings without overstating organizational readiness.

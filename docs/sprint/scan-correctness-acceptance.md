# Scan-correctness acceptance report

**Status: CORE ACCEPTANCE RECORDED WITH THE SC-095 TOOL BOUNDARY.** Draft [PR #56](https://github.com/cozyGarage/sentinelflow/pull/56) carries this work. All named CI jobs, race/vet/integration gates, the SC-095 qualification/inventory job, and security workflow passed on exact head `43edb9ea63808902422804c7c5f9a328e85d54bc`: [CI run 39047307186](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307186), [security run 39047307188](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307188). SC-095 is resolved under its explicit acceptance criterion: unavailable versions stay unqualified; pinned govulncheck behavior is locally and hosted-fixture-qualified. The six unavailable scanner integrations remain follow-up qualification work and are not represented as ready for organizational rollout. This report update triggers another exact-head run; the [PR checks page](https://github.com/cozyGarage/sentinelflow/pull/56) is authoritative for its result.

Prepared 2026-10-17. Repository: `/home/trung/Projects/sentinelflow`. Checked-out branch: `codex/scan-correctness-sprint`. Base HEAD: `cdd7cd7c390c65809fcd08e10dd0492360579565`. The implementation source was validated at `3e128766b4e497136984bb0f9fbcafe9d91e7693`; the exact-head hosted acceptance run is recorded below.

## Core item status

`Local evidence` means a focused deterministic check passed in this implementation worktree. It does not close the item until all acceptance conditions and exact-revision hosted evidence are met.

Hosted coverage: [CI run 39047307186](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307186) passed on `43edb9ea63808902422804c7c5f9a328e85d54bc`. The 37 matrix selectors provide named coverage for every core ID assigned a matrix row; the same run passed SC-094 integration, SC-095 govulncheck/inventory, SC-099 exact-head gates, and SC-100 reconciliation. The security workflow passed in [run 39047307188](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307188). Use the PR checks page for the current head after this report update.

| ID | Status | Current evidence / remaining work |
| --- | --- | --- |
| SC-001 | Local baseline and named Actions check | Clean checkout and Go 1.27.2 were recorded by the SC-001 job in hosted CI run [39047307186](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307186), which passed on accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc`. The current revision is verified through the PR checks page. |
| SC-002 | Local and hosted evidence | Fake tools cover findings then failure, truncation, clean completion, cancellation, args, baseline failures and cleanup; named matrix rows passed in hosted CI run 39047307186. |
| SC-003 | Local and hosted evidence | Inventory, identity, unknown, comparison and exit decisions are written in the plan/compatibility notes; named exit-contract row passed in hosted CI run 39047307186. |
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
| SC-043 | Local and hosted evidence | Exact advisory/module/version matching, alias and symbol-level requirements tested. Pinned govulncheck v1.9.0 was exercised against local synthetic DB/module fixtures: called symbol is reachable; imported-only and absent observations stay unknown; a missing `go.mod` produces an error and remains unknown. Named regression and qualification jobs passed in hosted CI run 39047307186. |
| SC-044 | Local evidence | Unknown/reachable gates fail closed; required error is not softened; partial head finding is retained. |
| SC-051 | Local evidence | Head/base asymmetric fake failures reject comparison; scanner run error can coexist with nil engine error. |
| SC-052 | Local evidence | Missing/failed/mismatched outcomes rejected; complete comparable scan retains line-motion behavior. |
| SC-053 | Local evidence | Fresh scanner instances and scanner set comparability tested. |
| SC-054 | Local evidence | Cancellation cleanup, injected cleanup error, invalid ref, caller checkout state and successful cleanup tested. |
| SC-091 | Local evidence | Built CLI checks clean `0`, finding `1`, operational `2`, deadline `3`, report and partial-result behavior. |
| SC-092 | Local evidence | Built CLI times out after parseable tool output, writes partial report and returns `3`. |
| SC-093 | Local evidence | Threshold plus incomplete baseline exits `2`; unknown reachability plus failed base scan retains risk. |
| SC-094 | Configured; all local selectors and integration passed | `actionlint` passes; all 37 selector rows parsed from the current workflow matrix ran and matched tests through the zero-match guard; a deliberately nonexistent selector fails; tagged suite passed locally. Hosted CI run [39047307186](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307186) passed every matrix and integration job on accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc`. |
| SC-095 | Resolved under its explicit availability boundary | Pinned govulncheck v1.9.0 passed local and hosted synthetic reachable/imported-only/absent and missing-module cases. The hosted inventory recorded Semgrep, Gitleaks, Grype, Syft, Trivy, YARA and standalone govulncheck unavailable; the six external integrations remain unqualified as the acceptance criterion requires. See [tool matrix](real-tool-qualification.md). |
| SC-097 | Local documentation and hosted evidence | Go/npm, baseline/fingerprint, adapter, reachability and exit compatibility notes are written; all named workflow checks passed on the accepted head. Broader unsupported coverage remains listed as follow-up. |
| SC-098 | Local evidence | Failing-first tests showed diagnostic leakage in engine and text/JSON/SARIF output, including a pre-result VEX load error leaking a marker from the target path through CLI stderr. Engine, reporter, and top-level CLI scan errors now redact it; built-CLI marker checks pass. |
| SC-099 | Exact-head evidence passed | Draft [PR #56](https://github.com/cozyGarage/sentinelflow/pull/56) is open. CI race/vet/integration/helper gates passed at accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc` in [run 39047307186](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307186); the security workflow passed in [run 39047307188](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307188). The report-only change now in progress triggers another exact-head run. |
| SC-100 | Reconciled and handed off | [Proposed next assignment](next-assignment.md) orders follow-up risks and preserves readiness limits. `scripts/check-scan-sprint-docs.py` verifies all 32 core IDs have backlog rows, acceptance rows and named Actions coverage; four Python regressions cover valid docs, missing acceptance, missing job, and duplicate acceptance. Local tests and hosted reconciliation passed in CI run [39047307186](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307186) at accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc`; this report-only update triggers another run. |

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
| `go test -tags=integration -count=1 ./test/...` | Pass locally and in the hosted SC-094/SC-099 jobs at accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc`; this test path may contact advisory services and is not a deterministic mock-only suite. |
| `bash scripts/install_checksum_test.sh`; `bash scripts/pr_comment_test.sh` | Both pass on current worktree. |
| `actionlint .github/workflows/ci.yml`; YAML parse; `git diff --check` | Pass after the current matrix and job additions. |
| `bash scripts/qualify-govulncheck.sh` | Pass locally against pinned govulncheck v1.9.0 and local synthetic module/DB fixtures; called=true, imported-only=unknown, absent=unknown, missing `go.mod`=operational error with unknown reachability. |
| `bash scripts/run-go-test-selector.sh ./internal/scanner/dependencies 'TestSC043_(GovulncheckNegativeRequiresQualifiedPackageObservation|NonSymbolScanCannotEstablishUnreachable)'` | Pass; both named tests were observed in JSON test events. A deliberately nonexistent selector failed with `no tests matched`, confirming green-with-no-tests is rejected. |
| Current `.github/workflows/ci.yml` `scan-correctness` matrix via `scripts/run-go-test-selector.sh` | Pass, 37 of 37 configured selector rows executed at least one passing test on the current source. The final rerun used `/home/trung/.cache/tmp` and loopback-enabled execution because `/tmp` quota and the default sandbox blocked temp writes and `httptest` listeners. This local selection audit does not replace hosted Actions. |
| `python3 scripts/test_scan_sprint_docs.py`; `python3 scripts/check-scan-sprint-docs.py` | Pass: all four SC-100 positive/negative tests and the 32-ID positive audit pass locally. |
| SC-001 clean-checkout baseline step | Pass at `347dbeee6c3c3574e38933918e257056545aec03`: worktree clean, revision recorded, and `go version` reported Go 1.27.2 linux/amd64. |
| Built CLI `TestSC091_BuiltCLIExitAndPartialReport/pre-result_engine_error_redacts_sensitive_target_path` | Failing-first: a missing VEX file exposed a synthetic API-key marker on stderr. After redacting top-level engine errors, the CLI returns exit `2`, omits the short marker, and retains a useful redacted `load VEX` reason. The short marker avoids triggering the repository's own secret scan. |
| `test -z "$(gofmt -l .)"` | Pass after formatting the Go fixture modules. |

The Go race suite, vet, tagged integration suite, pinned govulncheck fixture and all 37 test selectors passed locally. The hosted CI and security workflows then passed on accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc`. The current report-only update triggers another run; exact live results are linked from the PR checks page.

## Hosted and upstream-tool evidence

- Hosted Actions: CI and security passed on accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc` in [run 39047307186](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307186) and [run 39047307188](https://github.com/cozyGarage/sentinelflow/actions/runs/39047307188). Earlier security failures came from the long synthetic test marker also quoted in this report; both values are now short. This report-only update triggers another run; use [PR #56 checks](https://github.com/cozyGarage/sentinelflow/pull/56) for the live exact head.
- Real tools: **resolved with explicit qualification limits**. Pinned govulncheck v1.9.0 passed local and hosted synthetic fixtures. Local and hosted inventories found Semgrep, Gitleaks, Grype, Syft, Trivy and YARA unavailable; these six remain unqualified as allowed by SC-095. Fake executable tests validate SentinelFlow control flow only. See [real-tool-qualification.md](real-tool-qualification.md). No claim of production parity or organizational readiness is made.
- Integration tests: local tagged run passed; the hosted SC-094 and SC-099 jobs also passed on accepted head `43edb9ea63808902422804c7c5f9a328e85d54bc`.

## Public behavior and remaining risks

Compatibility changes and limitations are recorded in [compatibility.md](compatibility.md). Go requirements are not represented as a fully selected graph. npm finding IDs distinguish installation paths. Modern baseline fingerprints no longer fall back to weak line-sensitive hashes. Partial reports accompany nonzero operational/deadline outcomes. Scanner diagnostics are redacted in engine outcomes and reports.

The 32-item core is accepted when this reconciliation change passes the named hosted gates. SC-095's six unavailable external tools remain explicitly unqualified and must be installed/pinned and tested before their integrations are treated as production-qualified. That limitation and the next assignment prevent this sprint result from implying organizational rollout readiness.

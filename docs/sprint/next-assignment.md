# Proposed follow-up assignment

Status: **SC-100 handoff prepared**. This orders the next work after the scan-correctness core. It does not imply organizational rollout readiness; confirm pilot scope and assign an owner when starting the follow-up.

## First follow-up: explicit scan outcome and coverage (SC-004–SC-006)

Add an additive, compatibility-aware representation for complete, partial, failed, timed-out, not-applicable and skipped analysis. Trace how collection, native scanners, optional/required adapters, dependencies and reachability move that state through the engine, API, CLI and reports. Define which profiles may accept degraded coverage and make required profiles fail closed. Keep a valid clean result distinguishable from a scanner that never ran.

Start with a table-driven outcome matrix across scanner modes, dependency `fail_on_error`, missing binaries, malformed reports, cancellation and partial findings. Preserve existing JSON fields and add any new fields as optional; document migration before consumers depend on them. This is the next prerequisite because the current core records many failures in `ScannerRun.Error` but does not give every result a single explicit completeness contract.

## Subsequent batches

1. **Suppression identity and retained evidence (SC-071–SC-080).** Qualify ecosystem-aware VEX identity, aliases, broad scope, expiry, ignored-file semantics and audit-safe suppression reasons. This is necessary before organizations rely on exceptions as governance.
2. **Vulnerability data quality (SC-081–SC-090).** Carry source and snapshot age, define offline freshness, unsupported range behavior, and retain per-package lookup failures. Keep live advisory drift separate from deterministic fixtures.
3. **Inventory depth and coverage (SC-015–SC-018, SC-025–SC-030, SC-065–SC-070).** Add opt-in selected Go graph/workspace resolution, qualify other ecosystem lockfiles, expose skipped file/package coverage and native SAST degradation. Make no whole-repository or artifact coverage claim without measured evidence.
4. **Staged/diff integrity (SC-055–SC-067).** Pin baseline refs, qualify monorepo paths and compatible rule/data snapshots, preserve staged index state, and make scanner timeouts and result filtering explicit.
5. **Resource and production tool qualification (SC-035–SC-050, SC-096).** Bound process output/resources and run pinned real-tool matrices on a permitted runner. Keep each unavailable version explicitly unqualified.

## Readiness boundary

The current sprint repairs selected false-pass paths and adds local evidence. Before a mandatory organization-wide gate, require final hosted checks on the exact sprint revision, real-tool qualification for advertised integrations, explicit outcome/coverage policy, reviewed suppression authority, data freshness behavior and consumer compatibility evidence. Preserve the distinction between a technically reliable local scanner and an organizationally governed CI control.

# Scan correctness work package

**Status: the 14-day core is complete (32/32); follow-up work remains active.** In the 100-item backlog, 28 follow-up items are also merged, for **60/100 closed** and **40 follow-up items open**. The next recommended assignment is SC-068, which is a prerequisite for SC-020. SC-095 remains bounded to pinned govulncheck fixtures; six external tools remain unqualified. No organization-wide scanner-readiness claim is made.

| Scope | Closed | Progress |
| --- | ---: | --- |
| 14-day core | 32/32 | Merged in [PR #56](https://github.com/cozyGarage/sentinelflow/pull/56), accepted under the documented SC-095 boundary. |
| Follow-up backlog | 28/68 | SC-004–SC-006 in [PR #57](https://github.com/cozyGarage/sentinelflow/pull/57); SC-071–SC-075 in [PR #58](https://github.com/cozyGarage/sentinelflow/pull/58); SC-076–SC-080 in [PR #59](https://github.com/cozyGarage/sentinelflow/pull/59); SC-081–SC-090 and SC-015–SC-018 in [PR #60](https://github.com/cozyGarage/sentinelflow/pull/60); SC-019 in [PR #61](https://github.com/cozyGarage/sentinelflow/pull/61). |
| Full backlog | 60/100 | **40 remain:** SC-007–SC-010, SC-020, SC-025–SC-030, SC-035–SC-040, SC-045–SC-050, SC-055–SC-070, and SC-096. |

Latest checkpoint: current `main` is `33f33f9` (tree `dec8b3e`), identical in content to the checked head of [PR #62](https://github.com/cozyGarage/sentinelflow/pull/62). All 111 hosted checks passed on that head; see the [SC-019 acceptance record](go-version-selection-acceptance.md) for run links. Current-main local verification is recorded in the [core acceptance report](scan-correctness-acceptance.md).

This package develops the readiness review into one developer's **14-working-day plan** and a **100-item assignment backlog**. The core is 32 dependency-ordered items; the other 68 are follow-up work, not extra scope for the same timebox.

- [14-day developer plan](scan-correctness-14-days.md): sequence, daily outcomes, PR boundaries and completion checklist.
- [100-item backlog](scan-correctness-backlog.md): stable IDs, dependencies, implementation direction and acceptance criteria.
- [Acceptance report](scan-correctness-acceptance.md): per-core-item evidence, latest local/hosted checkpoint, and explicit real-tool limits.
- [Compatibility notes](compatibility.md): behavior changes, identity/baseline implications and supported boundaries.
- [Real-tool qualification](real-tool-qualification.md): exact command/version evidence and unavailable-tool limits.
- [Proposed next assignment](next-assignment.md): ordered work after the core.
- [Scan outcome contract](scan-outcome-contract.md): compatibility, status semantics, failure retention and consumer migration for SC-004–SC-006.
- [Scan outcome acceptance](scan-outcome-acceptance.md): implementation scope, local evidence and hosted gate boundary for SC-004–SC-006.
- [VEX suppression identity](vex-suppression-identity.md): supported PURL identity, explicit broad-scope migration, aliases and expiry semantics for SC-071–SC-075.
- [VEX suppression acceptance](vex-suppression-acceptance.md): behavior changes, compatibility migration and local/hosted evidence for SC-071–SC-075.
- [Suppression audit and identity](suppression-audit-identity.md): retained redacted observations, strict inline-ignore policy, collision-resistant fingerprints and path boundaries for SC-076–SC-080.
- [Suppression audit acceptance](suppression-audit-acceptance.md): implementation evidence and exact-head hosted status for SC-076–SC-080.
- [Vulnerability data provenance](vulnerability-data-provenance.md): OSV snapshot identity, acquisition time, live/cache/offline source modes and report boundaries for SC-081.
- [Vulnerability data acceptance](vulnerability-data-acceptance.md): local and hosted evidence for SC-081.
- [Offline freshness policy](offline-freshness.md): strict-mode configuration, age semantics and failure behavior for SC-082.
- [Offline freshness acceptance](offline-freshness-acceptance.md): local and hosted evidence for SC-082.
- [Version comparator support](version-comparator-support.md): explicit ordering capability and conservative unsupported-version behavior for SC-083.
- [Version comparator acceptance](version-comparator-acceptance.md): local and hosted evidence for SC-083.
- [GIT range support](git-range-support.md): explicit unassessed behavior and exact-version fallback for SC-084.
- [GIT range acceptance](git-range-acceptance.md): local and hosted evidence for SC-084.
- [OSV interval boundaries](osv-interval-boundaries.md): defined range boundary and withdrawal behavior for SC-085.
- [OSV interval acceptance](osv-interval-acceptance.md): local and hosted evidence for SC-085.
- [Online/offline advisory parity](online-offline-parity.md): shared pinned fixture and tuple matrix for SC-086.
- [Online/offline parity acceptance](online-offline-parity-acceptance.md): local and hosted evidence for SC-086.
- [Offline database update safety](offline-db-update-safety.md): archive/index limits and atomic writer/reader behavior for SC-087.
- [Offline database update acceptance](offline-db-update-acceptance.md): local and hosted evidence for SC-087.
- [Batch query partial results](batch-query-partial-results.md): alignment, partial findings, and cache policy for SC-088.
- [Batch query acceptance](batch-query-acceptance.md): local and hosted evidence for SC-088.
- [Risk enrichment completeness](risk-enrichment-completeness.md): required KEV versus optional EPSS/KEV behavior for SC-089.
- [Risk enrichment acceptance](risk-enrichment-acceptance.md): local and hosted evidence for SC-089.
- [Lookup cache isolation](lookup-cache-isolation.md): source, tuple, schema, and offline snapshot cache namespaces for SC-090.
- [Lookup cache acceptance](lookup-cache-acceptance.md): local and hosted evidence for SC-090.
- [Go module graph resolution](go-module-graph-resolution.md): opt-in selection, network policy, attribution, and unsupported workspace/replacement boundaries for SC-015.
- [Go module graph acceptance](go-module-graph-acceptance.md): local and hosted evidence for SC-015.
- [Versioned Go replacements](versioned-go-replacements.md): dual-coordinate advisory lookup and original declaration attribution for SC-016.
- [Versioned Go replacement acceptance](versioned-go-replacements-acceptance.md): local and hosted evidence for SC-016.
- [Local Go replacements](local-go-replacements.md): explicit fail-closed inventory policy for local and unversioned replacement targets in SC-017.
- [Local Go replacement acceptance](local-go-replacements-acceptance.md): local and hosted evidence for SC-017.
- [Go workspace resolution](go-workspace-resolution.md): workspace membership, selected versions, replacement policy, and stable source attribution for SC-018.
- [Go workspace acceptance](go-workspace-resolution-acceptance.md): local and hosted evidence for SC-018.
- [Go version selection](go-version-selection.md): pseudo-versions, major path suffixes, excluded versions, and toolchain boundaries for SC-019.
- [Go version selection acceptance](go-version-selection-acceptance.md): local and hosted evidence for SC-019.

The core acceptance report records its exact historical revision and hosted evidence. Follow-up slices have their own acceptance files and exact-head run links. Current repository state is authoritative; use `git status --short --branch` and `git rev-parse HEAD` before assigning or accepting work.

## Evidence and current limits

The workflow has a named regression row for every core ID and merged follow-up selectors SC-004–SC-006, SC-015–SC-019, and SC-071–SC-090. `SC-001` records the exact checkout and Go toolchain. Separate named jobs cover `SC-094` integration, `SC-095` govulncheck/tool inventory, `SC-099` exact-head gates, and `SC-100` backlog/acceptance/handoff reconciliation. Selector rows fail if no test executes. `scripts/check-scan-sprint-docs.py` checks all core IDs across backlog, acceptance and named Actions; its CI test suite includes missing-row and missing-job negative controls.

The completed core and merged follow-up slices have local and hosted evidence in their acceptance records. SC-076–SC-080 passed full Go tests, race suite, vet, actionlint, documentation tests and eleven named selector rows; see its acceptance record for hosted exact-head evidence. SC-081–SC-090 and SC-015–SC-018 passed local gates and merged in PR #60 after all 110 hosted checks passed on the final head. SC-019 passed local gates and merged in PR #61. The later docs-only [PR #62](https://github.com/cozyGarage/sentinelflow/pull/62) reran the full suite and passed all 111 checks on a tree identical to current `main`; the latest current-main local gate results are in the core acceptance report.

`SC-095` is resolved under its documented boundary: pinned govulncheck behavior is qualified against synthetic fixtures, and Semgrep, Gitleaks, Grype, Syft, Trivy and YARA are explicitly marked unavailable and unqualified in local and hosted inventories. This does not qualify those integrations or support an organization-wide readiness claim.

The CI workflow runs on pull requests targeting `main` or `develop`, pushes to `main`, and manual dispatch. Hosted evidence is recorded per exact head in the relevant acceptance report; runs on superseded heads do not close exact-head gates. Follow-up PRs are merged only after all required checks pass on the final documentation-inclusive head.

For assignment, retain the backlog dependencies and attach the reproducer, positive control, failing-first result, named local/hosted evidence, compatibility impact, and unresolved boundaries. The backlog is the acceptance source of truth; this README is the compact status index.

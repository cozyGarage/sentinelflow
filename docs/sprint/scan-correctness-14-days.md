# Scan correctness: one developer, 14 working days

Status: **in progress**. Go inventory, npm package-instance identity, external adapter outcomes, reachability, baseline-ref comparison, and built-CLI exit work have local implementation and regression evidence. The full core is not accepted: hosted Actions remain unrun, six optional scanner integrations are unqualified, and the final handoff is incomplete. Pinned govulncheck has a local synthetic-fixture qualification. Current evidence is tracked in the [sprint README](README.md); this file remains the authoritative 14-day scope and acceptance workflow. Prepared 2026-10-17 against the [source review](../organizational-readiness.md). The [backlog](scan-correctness-backlog.md) is the authoritative issue list.

## Outcome

Deliver a trustworthy core path for **Go require inventory, npm package-lock inventory, external tool completion, Go reachability and baseline-ref comparison**. A selected package version must not come from historical checksum ordering; multiple installed package versions must survive inventory; an incomplete required analysis must never become a clean or reduced-risk decision.

This increment repairs F01–F03 and their immediate CLI integration. It does not resolve all organizational readiness findings. In particular, mandatory organizational rollout remains blocked on the separate suppression/policy, coverage and consumer qualification work described in the broader plan.

### Core selection: 32 items

| Area | IDs | Count | Required outcome |
| --- | --- | --- | --- |
| Baseline and contract | SC-001–SC-003 | 3 | Reproducible starting evidence, deterministic fixtures and agreed invariants. |
| Go inventory | SC-011–SC-014 | 4 | Module-aware require parsing, no checksum override, explicit limitation on unsupported resolution. |
| npm inventory | SC-021–SC-024 | 4 | Preserve multiple versions and recurse npm v1 trees deterministically. |
| External execution | SC-031–SC-034 | 4 | Tool-specific exit/parse contracts; findings never hide operational failures. |
| Reachability | SC-041–SC-044 | 4 | Failed/incomplete runs remain unknown and cannot weaken reachable-only gating. |
| Baseline-ref | SC-051–SC-054 | 4 | Both scan sides must be complete/comparable; failures do not erase head evidence. |
| Qualification and handoff | SC-091–SC-100, excluding SC-096 | 9 | Real CLI regressions, focused CI, redaction check, compatibility evidence and final handoff. |
| **Total** | | **32** | |

Every range above is inclusive. The other 68 backlog items are follow-up, including SC-096's explicit performance harness. The core still records obvious timing/resource regressions during qualification; it does not establish a production performance SLA.

## Scope decisions before implementation

1. **Inventory truth:** the core parses Go `require` entries accurately and labels their source. It does not claim they are a complete selected transitive graph. Do not replace the existing `go.sum` approximation with silent under-coverage. Surface the reduced/unsupported resolution explicitly; if the selected mandatory profile requires a resolved graph, return an operational error until that evidence is available. Full graph/workspace support is SC-015–SC-018.
2. **npm identity:** use ecosystem, name, version and manifest/install location when available. Share package matching where safe, while retaining all location instances for findings. Do not deduplicate by name or name/version alone when that erases meaningful locations.
3. **Tool completion:** accepted exits depend on the exact invoked command/tool version, not a universal rule that exit `1` means findings. A fake executable validates behavior deterministically; qualify actual supported tool semantics separately before advertising support.
4. **Reachability:** unknown is preserved on command failure, malformed output or unsupported evidence. “No symbol observed in a completed analysis” is not a universal proof of unreachability. Do not infer `false` from a missing advisory match without a justified correlation rule.
5. **Comparison:** validate both base and head execution outcomes before suppressing pre-existing findings. If completeness cannot be established, report comparison failure and retain head evidence. Do not return a filtered report that appears complete.
6. **Compatibility:** prefer narrow helpers and additive fields over a new engine or public schema rewrite. Version or migrate any changed identity or baseline matching behavior; do not regenerate all baselines simply to make regression tests pass.

Record these decisions under SC-003, with concrete current API behavior. If a prerequisite requires a larger data-model change, narrow supported scope explicitly and carry that decision into the handoff. Do not quietly weaken the acceptance criterion to meet day 14.

## Daily execution plan

Assume one developer with ordinary review turnaround. The plan uses approximately 10 implementation days and 4 days for investigation, integration, review and contingency; individual tasks may overlap within a day. Review delays or inaccessible tools can extend elapsed time.

| Day | Assignment | Expected reviewable result | Dependency / stop condition |
| --- | --- | --- | --- |
| 1 | SC-001–SC-003 | Exact starting revision/state, runnable focused checks, invariant decisions and fixture conventions. Reproduce the highest-risk paths before fixes. | If storage/access blocks tests, diagnose and report; do not delete unrelated caches or call the baseline green. |
| 2 | SC-011–SC-012 | Failing regressions for checksum override and module syntax; narrow Go parser repair. | Preserve findings on valid existing supported fixtures. |
| 3 | SC-013–SC-014 | Explicit handling of missing/malformed sums and unsupported resolution; provenance/coverage behavior, Go PR ready. | No falsely complete transitive inventory. |
| 4 | SC-021–SC-022 | npm v2/v3 fixture with safe/vulnerable same-name versions; corrected identity and deterministic traversal. | Review distinct install-location retention. |
| 5 | SC-023–SC-024 | Recursive npm v1 and end-to-end inventory/finding attribution; npm PR ready. | Both installed versions must reach mocked advisory matching. |
| 6 | SC-031–SC-032 | Accepted-exit contracts and fake-tool matrix; crash-after-findings regression repaired. | Findings alone cannot establish success. |
| 7 | SC-033–SC-034 | Empty/malformed/truncated parse behavior, required/optional engine/CLI assertions; adapter PR ready. | Required incomplete tools never pass. |
| 8 | SC-041–SC-042 | Reachability preamble/failure and malformed/cancelled stream regressions; preserve unknown state. | Do not treat message count as completion. |
| 9 | SC-043–SC-044 | Complete-run advisory correlation and reachable-only gate tests; reachability PR ready. | No absent/unmatched analysis becomes false by default. |
| 10 | SC-051–SC-052 | Base/head failure reproducers and narrow completeness validator. | Preserve head findings even when comparison fails. |
| 11 | SC-053–SC-054 | Comparable config/scope checks and temporary worktree cleanup; comparison PR ready. | Do not accidentally reuse mutable scanner state or mutate caller checkout. |
| 12 | SC-091–SC-094 | Built CLI exit matrix, combined fault cases, public output/identity snapshots and mandatory focused CI. | Test actual process exits, not only `RunE` return values or reimplemented gates. |
| 13 | SC-095, SC-097–SC-098 | Supported tool contract matrix, negative-case evidence, compatibility notes and leakage regression; review fixes. | Missing real-tool evidence remains explicitly unqualified. |
| 14 | SC-099–SC-100; complete outstanding core checks | Final exact-head validation, acceptance report, remaining-risk handoff and assignment status. | If a core invariant fails, mark incomplete and carry it forward with a reproducer. |

## PR boundaries

Use approximately six cohesive PRs; test tasks can land with their implementation PR. Stable issue IDs do not require one PR per item. Do not merge red tests separately into a required green branch merely to demonstrate failing-first work; retain the pre-fix failure evidence in the PR.

| PR | Scope | Required review focus |
| --- | --- | --- |
| A | SC-001–003, SC-011–014 | Go inventory semantics and explicit degraded coverage; no network/build execution introduced implicitly. |
| B | SC-021–024 | Distinct versions/locations, recursion, deterministic output and unchanged dev dependency policy. |
| C | SC-031–034 | Per-tool exit classification, malformed output and finding/error preservation. |
| D | SC-041–044 | Analysis completion, alias mapping and unknown reachability gate behavior. |
| E | SC-051–054 | Both-side validation, retained head result, worktree cleanup and scanner state isolation. |
| F | SC-091–095, SC-097–100 | CLI/CI regressions, compatibility, output leakage and final exact-head evidence. |

Revalidate dependent PRs after changes to shared outcome/identity helpers. Keep changes scoped to existing scanner/CLI/reporting boundaries. Do not redesign every scanner to fix one adapter.

## Regression and acceptance matrix

These scenarios define behavior, not exact test function names. Connect each to the named issue and actual test location in the handoff. Positive controls are mandatory: a system that rejects every scan also fails this package.

| Scenario | Expected evidence and decision | Owner items |
| --- | --- | --- |
| Go requires current version; sums contain old and new versions in either order | Current declared version stays current; checksum-only versions never masquerade as resolved dependencies. | SC-011–014 |
| Go syntax includes inline require, grouped require and comments | Module-aware parser returns exact entries with valid source locations; malformed input produces visible error. | SC-012–013 |
| Go resolution requires replacements/workspace state outside core support | Explicit unresolved/degraded coverage; mandatory resolved-graph profile cannot pass. | SC-014 |
| npm v2/v3 installs both safe and vulnerable versions of one name | Both components queried; vulnerable instance/location retained independent of map order. | SC-021–022, SC-024 |
| npm v1 nested dependency contains the only vulnerable version | Recursive parsing finds it; root entries and nested attribution retained. | SC-023–024 |
| Tool completes with findings and an accepted finding exit | Findings retained; engine completion succeeds; severity policy can return `1`. | SC-031–032 |
| Tool emits findings then exits with an operational error | Findings and failure retained; required scanner yields operational failure. | SC-032–034 |
| Tool exits zero with malformed/empty output where structured report is required | Error rather than “zero findings”; optional degradation visible under existing allowed policy. | SC-033–034 |
| Reachability emits preamble/finding then fails or truncates | Candidate observations remain unknown; `reachable_only` cannot drop them. | SC-041–044 |
| Reachability completes and yields a qualified symbol/alias match | Reachable association is correct and scoped; unrelated advisories remain unknown unless explicitly assessed. | SC-043 |
| Base scan fails but head is complete, or vice versa | No valid delta decision; preserve available head observations and record comparison error. | SC-051–053 |
| Both sides complete and share required coverage; old finding moves line | Existing line-independent comparison still works; new qualifying finding still blocks. | SC-052–053 |
| Comparison times out or cannot create worktree | Operational/timeout outcome; cleanup is attempted with bounded context; caller files unchanged. | SC-054, SC-091 |
| Clean complete scan, threshold finding, tool failure, deadline failure | Actual CLI returns respectively `0`, `1`, `2`, `3` under documented precedence. | SC-091–093 |
| Sensitive value appears in a scanner diagnostic | No raw secret in public error/report/log fixtures; useful bounded reason retained. | SC-098 |

## Validation workflow

Run focused tests after each repair. Run the broader checks after integration and after subsequent changes that could invalidate their result. Use the checkout's required Go toolchain and a writable, scoped cache; do not share one mutable test fixture across concurrent runs.

```bash
# Focused packages; narrow further during individual issue work.
rtk go test ./internal/scanner/dependencies ./internal/adapter/external ./internal/scanner ./internal/cli ./internal/reporter ./pkg/api

# Exact-head core qualification.
rtk go test -race ./...
rtk go vet ./...

# Integration-tag suite; isolate/mask live services with fixtures where needed.
rtk go test -tags=integration ./test/...

# Existing delivery helpers affected by CLI/report behavior.
rtk proxy bash scripts/install_checksum_test.sh
rtk proxy bash scripts/pr_comment_test.sh
rtk git diff --check
```

The existing integration-tag suite may involve advisory lookups; classify network-dependent results separately and convert core correctness cases to deterministic local fakes. A skipped, blocked or cached historical result is not current proof. Do not modify the fixture corpus in place during concurrent suites; use test temporary directories.

Use a real built CLI binary in SC-091; capture stdout, stderr, report and process status from the same invocation. Keep fixtures synthetic, no live credential verification. Mock OSV responses must assert the queried package/version set, not just the number of findings returned. Tool fakes must assert arguments and distinguish accepted finding exits from operational failures.

No new performance claim is required. Capture obvious resource regressions from existing checks and move measurement work to SC-096 if needed. Live external-tool qualification can be run on a permitted environment; a missing binary means the adapter remains unqualified, not that its behavior has passed.

## Completion checklist and handoff

- [ ] All 32 core IDs closed with evidence, or explicitly listed as incomplete with impact and next action.
- [ ] Each repaired defect has a pre-fix failing reproducer and post-fix passing regression.
- [ ] Positive complete/clean and complete/finding cases still work.
- [ ] Invalid inventory or incomplete mandatory scans cannot return a valid pass or suppress risk.
- [ ] Raw findings survive partial tool/comparison failures where a partial result can be produced.
- [ ] Exact package versions, ecosystem and locations are retained across query, finding and SBOM consumers in the repaired scope.
- [ ] Baseline/fingerprint/API compatibility effects documented; no silent baseline reset.
- [ ] Public outputs do not leak seeded sensitive values.
- [ ] Focused checks, race suite, vet, integration suite and helper checks recorded individually with exact revision.
- [ ] Hosted CI and real-tool qualification recorded separately; unrun checks remain visible.
- [ ] Follow-up IDs have an order and rationale; readiness is not upgraded beyond demonstrated scope.

SC-099 should create `scan-correctness-acceptance.md` in this directory **at implementation time**, with: revision; closed/incomplete IDs; PR links; reproduced defects; commands/results; supported tool/version matrix; public compatibility changes; known unsupported coverage; remaining risks; and recommendation for the next assignment. Do not pre-create a document that looks like successful acceptance evidence.

## Contingency and explicit exclusions

If setup consumes more than one working day, or core model changes exceed the agreed scope, re-estimate the remaining core work and record incomplete items. Do not trade away findings-on-error, unknown reachability or both-side completeness. These are acceptance boundaries.

Follow-up backlog covers full Go resolution/workspaces, classic Yarn and pnpm hardening, process/output limits, staged snapshots, SSA degradation, VEX identity, coverage provenance, DB freshness and offline parity. External backend integrations, runtime agents, dashboards, AI review, release publication redesign and organizational approval infrastructure remain outside this 14-day assignment.

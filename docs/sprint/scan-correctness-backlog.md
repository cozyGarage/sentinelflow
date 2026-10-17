# Scan correctness backlog: 100 assignable items

Prepared 2026-10-17. **The assignment backlog records a 32-item core and 68 follow-ups.** Named Actions regression rows cover `SC-002`, `SC-003`, `SC-011`–`SC-014`, `SC-021`–`SC-024`, `SC-031`–`SC-034`, `SC-041`–`SC-044`, `SC-051`–`SC-054`, `SC-091`–`SC-093`, and `SC-097`–`SC-098`. Separate jobs cover integration (`SC-094`), real-tool qualification/inventory (`SC-095`) and exact-head gates (`SC-099`). Hosted CI [run 39049882098](https://github.com/cozyGarage/sentinelflow/actions/runs/39049882098) and security [run 39049882006](https://github.com/cozyGarage/sentinelflow/actions/runs/39049882006) passed on implementation head `23e245da4be46e76a1fbfe2bc7b1e094e8f528dd`. SC-095 explicitly leaves unavailable versions unqualified. Context: [source assessment](../organizational-readiness.md). Execution schedule: [14-day plan](scan-correctness-14-days.md).

**C** = 14-day core (32 items). **F** = follow-up (68 items), outside that timebox. IDs are stable. Copy an item's row, epic context and shared completion rules when creating an issue later. Dependencies are prerequisites, not authorization for parallel work. Related test and implementation items can share a PR.

Some items fix source-observed defects; others qualify a boundary or add missing evidence. Reproduce first. A qualification item can close without a code change if exact-revision evidence satisfies its criterion. Do not manufacture a refactor just to close an item.

## Shared completion rules

- Inspect the assigned checkout and existing tests/helpers before editing. Record the starting revision and unrelated changes.
- For a confirmed defect, retain pre-fix failure evidence and a passing post-fix regression, plus a positive control.
- Keep correctness tests deterministic: synthetic credentials, mocked advisory data, fake executables and temporary git repos. Live tool qualification is separate.
- Assert actual inventory, query tuples, stored identity and attributed findings; aggregate counts alone are insufficient.
- Preserve findings and operational errors together where evidence is available. Missing, partial or unsupported analysis is not successful empty analysis.
- Document API/fingerprint/baseline compatibility and unsupported scope. Prefer narrow existing boundaries over an engine rewrite.
- Attach exact revision, focused commands and results. Mark local, hosted, real-tool, blocked and unrun checks separately.

An operational failure must prevent a required scan from claiming success: normally tool/config exit `2`, or timeout `3` when a deadline caused it. Findings can coexist with either. Record the explicit precedence decision before changing shared gate behavior.

## A — Starting evidence and contracts

Surfaces: `pkg/api`, `internal/scanner/engine.go`, `internal/cli/scan.go` and their tests. Extend existing result/run boundaries; no new job framework.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-001 | C | **Establish a runnable baseline.** Inspect worktree, toolchain, storage, caches and existing checks; investigate quota only if it recurs. | Exact HEAD, unrelated edits and individual commands/results recorded. Focused tests can use writable temp/cache storage, or a concrete blocker is documented without deleting unrelated data. | None |
| SC-002 | C | **Prepare deterministic fault fixtures.** Reuse existing executable, advisory and temporary-repository helpers. | Fakes emit valid findings then fail, truncate JSON, wait for cancellation and return clean output; arguments are asserted. No real credential/network dependency. | SC-001 |
| SC-003 | C | **Record core invariants.** Define inventory provenance, package-instance identity, completion, unknown reachability, comparison and exits. | Decision note resolves narrow Go fallback support and `0/1/2/3` precedence; each invariant maps to a named regression. No implicit complete-transitive claim. | SC-001 |
| SC-004 | F | **Represent scanner outcome states explicitly.** Evaluate additive complete/partial/failed/timed-out/not-applicable/skipped status. | JSON compatibility tests distinguish valid zero findings from no execution. Outcome reflects actual execution; schema migration documented if needed. | SC-003, SC-034 |
| SC-005 | F | **Audit partial-result loss.** Trace engine/CLI post-processing, diff, VEX-load and report failures. | Path table identifies evidence survival; selected failure regressions retain findings and diagnostics. Cases with no safe report are explicit. | SC-003, SC-051 |
| SC-006 | F | **Reconcile required/optional degradation.** Review adapter modes and dependency `fail_on_error` together. | Off/auto/required and strict/non-strict failure matrix passes. Allowed degradation is visible; required failures cannot be converted into warnings. | SC-004, SC-034 |
| SC-007 | F | **Stabilize diagnostics and outcome ordering.** Audit concurrent and map-based aggregation. | Repeated shuffled inputs yield identical normalized findings/errors/warnings excluding documented timestamps; no scheduling-dependent expectations. | SC-022, SC-034 |
| SC-008 | F | **Qualify machine-output streams.** Prevent headers/logging from being mistaken for JSON. | Actual CLI captures for clean/denied/failed scans separate structured data from diagnostics; existing human output retained or deliberately migrated. | SC-091, SC-092 |
| SC-009 | F | **Publish capability boundaries.** Map supported formats, depth and exclusions to tests. | Every supported claim links to evidence; native/optional tooling and unsupported formats distinguished. `--all` is not interpreted as universal coverage. | SC-004, SC-065 |
| SC-010 | F | **Document correctness threat boundaries.** Trace untrusted repo/config/tool output/data to decisions. | Concrete false-pass, suppression, path and resource risks link to fixes or deferrals. No claim that documenting authority implements protected organizational policy. | SC-003 |

## B — Go inventory truth

Surfaces: `internal/scanner/dependencies/scanner.go`, `scanner_test.go`, shared dependency/SBOM consumers. Core repairs require inventory; full selected transitive resolution is follow-up.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-011 | C | **Prevent historical checksum version override.** Stop using the first `go.sum` version as selected-version truth. | Current require plus old/new full-module sums in either order keeps the declared version. Mock query set never promotes checksum-only entries to resolved transitives. | SC-002, SC-003 |
| SC-012 | C | **Parse requires with Go module-aware parsing.** Reuse the existing module dependency instead of expanding ad hoc line parsing. | Inline/grouped requires, comments and indirect entries retain exact versions/locations. Invalid syntax errors visibly; replacement/exclusion directives recognized for support decisions. | SC-011 |
| SC-013 | C | **Define missing/corrupt sum behavior.** Separate checksum errors from legitimate declared inventory. | Missing/unreadable/malformed sums, duplicate versions and `go.mod`-only entries produce deterministic outcomes. Valid requires survive where justified; unresolved transitive coverage remains explicit. | SC-012 |
| SC-014 | C | **Expose Go provenance and unresolved coverage.** Add the smallest compatible signal for declared versus resolved evidence. | Unsupported replacement/workspace/selection cannot claim full graph coverage or pass a profile requiring it. Query/finding attribution and documentation match supported scope. | SC-012, SC-013, SC-003 |
| SC-015 | F | **Implement opt-in selected graph resolution.** Evaluate controlled `go list -m -json all` or equivalent. | Fake command tests cover complete/error/timeout/missing-tool. Network/download policy explicit; no implicit repository build/install execution. Resolved inventory differs visibly from fallback. | SC-014, SC-004 |
| SC-016 | F | **Apply versioned replacements correctly.** Preserve declared and effective module identity. | Replacement name/version drives correct advisory queries; original attribution retained. No disappearing finding solely because replacement identity differs. | SC-015 |
| SC-017 | F | **Handle local replacements without invented versions.** Define scope for local source dependencies. | Local/nested replacements never query fabricated registry versions. Unversioned or outside-root inputs produce visible unresolved coverage under explicit policy. | SC-015, SC-016 |
| SC-018 | F | **Qualify workspaces and module roots.** Handle `go.work`, workspace replacements and subdirectory scans. | Two-module fixtures resolve intended membership/precedence once; deterministic provenance, no temporary checkout paths in persistent identity. | SC-015, SC-017 |
| SC-019 | F | **Cover Go version/selection edges.** Include pseudo-versions, major suffixes, excludes and toolchain modules. | Golden query tuples preserve exact supported versions/path identity. Unsupported cases explicit; normalization cannot silently alter advisory coordinates. | SC-015 |
| SC-020 | F | **Align Go SBOM and artifact consumers.** Reuse inventory with provenance rather than conflating source/build contents. | Controlled source and compiled binary fixtures retain distinct observed components. A source graph is never called proof of artifact contents. | SC-014, SC-015, SC-068 |

## C — Node package instances

Surfaces: `dependencies/scanner.go`, `lockfiles.go`, associated tests and `createFinding`. Advisory query deduplication must not erase distinct versions or locations.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-021 | C | **Keep npm v2/v3 multi-version instances.** Replace name-only package collapse. | Safe/vulnerable root/nested versions both survive; scoped names and same-version multiple installs keep meaningful locations. Assert stored instances, not count alone. | SC-002, SC-003 |
| SC-022 | C | **Make npm traversal deterministic.** Sort input keys or equivalent without selecting one arbitrary version. | Reordered lockfile keys repeatedly yield the same inventory/query set/findings; nested vulnerable version never lost. | SC-021 |
| SC-023 | C | **Recursively parse npm v1 dependency trees.** Replace top-level-only fallback with bounded traversal. | Vulnerable instance two levels deep reaches inventory with parent location; malformed nested entries cannot produce a complete-coverage claim. | SC-021 |
| SC-024 | C | **Retain npm identity through matching/output.** Check matching, findings, fingerprints and shared collection. | OSV mock sees both exact versions; affected instances retain correct locations in reports/baselines. Dev/prod policy unchanged; identity migration documented where required. | SC-022, SC-023 |
| SC-025 | F | **Preserve classic Yarn multi-version resolutions.** Fix name-only collapse and multi-selector headers. | Different selected versions both queried; repeated selectors for one resolution do not create accidental duplicates. Scoped names preserved. | SC-024 |
| SC-026 | F | **Detect unsupported Yarn Berry formats.** Avoid successful empty inventory for an unhandled lockfile. | Classic/Berry fixtures discriminated; unsupported format errors/degrades visibly. Claiming Berry support requires dedicated parser fixtures. | SC-025, SC-004 |
| SC-027 | F | **Qualify pnpm versions and peer keys.** Cover v5/v6/v9, namespaces and peer suffixes. | Distinct versions/instances retain exact coordinates; peer suffix processing does not erase a distinct component. Ordering/provenance deterministic. | SC-024 |
| SC-028 | F | **Separate manifest constraints from installed versions.** Review caret/tilde/range/git/file/workspace fallback. | No stripped range bound is called an exact installed version. Missing lockfile produces unresolved/declared coverage; strict resolved profile cannot pass. | SC-024, SC-014 |
| SC-029 | F | **Qualify dev dependency filtering.** Cover mixed prod/dev instances and pnpm importers. | `ignore_dev` cannot remove an instance needed by production. Compare exact query sets with toggle on/off; unknown scope not assumed development-only. | SC-027, SC-028 |
| SC-030 | F | **Qualify Node workspace/link scope.** Define nested locks, aliases and linked/optional inputs. | Workspace fixture preserves project identity despite overlapping names; no unbounded symlink traversal. Unresolved aliases/links remain visible. | SC-027, SC-028, SC-029 |

## D — External scanner completion

Surfaces: `internal/adapter/external/external.go`, parsers/tests, engine aggregation and CLI `scannerErrors`. Accepted exits apply to the exact invoked command/version, not remembered universal conventions.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-031 | C | **Define per-tool exit/output contracts.** Classify invoked Semgrep/Gitleaks/Grype/Syft/Trivy/YARA commands explicitly. | Matrix names executable/args/version, completion/finding exits and mandatory output. Fake tests cover each contract; unverified actual versions remain unqualified. | SC-002, SC-003 |
| SC-032 | C | **Preserve findings and command failure together.** Remove `len(findings)>0` as proof of success. | Tool emits finding then operational error/signal: both survive. Accepted finding exit remains completed analysis and can yield policy exit `1`. | SC-031 |
| SC-033 | C | **Reject malformed or incomplete required reports.** Make parse failure authoritative independently of process status. | Zero exit with bad/truncated/empty required JSON is error. Partial findings survive simultaneous parse/process failure; legitimate empty output accepted only by tool contract. | SC-031, SC-032 |
| SC-034 | C | **Verify adapter outcomes reach the gate.** Cover off/auto/required across engine and CLI. | Required missing/failed/incomplete tool never passes. Allowed optional degradation visible; original findings/diagnostics survive, including empty-result cases. | SC-032, SC-033 |
| SC-035 | F | **Bound tool stdout/stderr.** Replace unbounded capture where memory can grow without limit. | Flooding fake is stopped/limited; explicit truncation/incomplete status and bounded diagnostic retained. Resource ceiling measured and documented. | SC-034 |
| SC-036 | F | **Bound deadline/process-tree cleanup.** Qualify child processes and inherited open pipes. | Timeout fixture returns within bound, leaves no supported-platform child behind and preserves deadline cause for exit `3`. | SC-034, SC-035 |
| SC-037 | F | **Record and enforce tool version support.** Make existing version probe meaningful. | Missing/unknown/unsupported versions visible; strict profile rejects unqualified version. Fake probe covers timeout/error; result records actual tool/rule source. | SC-031, SC-036 |
| SC-038 | F | **Align adapters with requested scope.** Audit ignored `ScanOptions` and root-wide commands. | Inclusion/exclusion fixtures show exact applied scope or declared limitation; no false claim that required files were scanned. Preserve cross-file analysis context. | SC-034, SC-065 |
| SC-039 | F | **Control rule/config acquisition.** Audit registry downloads and repository tool configuration. | Rule source/digest and offline behavior recorded; inaccessible rules cannot become empty success. Network-disabled fixture proves contract. | SC-037 |
| SC-040 | F | **Fuzz external parsers.** Target nested JSON, hostile locations and malformed result fields. | Corpus plus fuzz smoke has no panic/unbounded growth. Invalid required output cannot establish successful coverage. | SC-033, SC-035 |

## E — Go reachability evidence

Surfaces: `dependencies/reachability.go`, its tests, engine enrichment and CLI `shouldFail`. Preserve nullable reachability semantics during additive changes.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-041 | C | **Reject failure after JSON preamble.** Replace message-count success inference with qualified completion. | Fake govulncheck emits valid config/OSV JSON then fails. Error propagates; candidate reachability stays unknown rather than all-false. | SC-002, SC-003 |
| SC-042 | C | **Handle broken/cancelled JSON streams.** Retain parse and process failures where both exist. | Truncated finding, malformed advisory, empty failure and cancellation keep unknown states. Valid complete clean stream is positive control. | SC-041 |
| SC-043 | C | **Require justified negative correlation.** Distinguish evaluated absence from missing/unrelated advisory data. | Positive symbol/alias mapping works; advisory/version/ecosystem mismatch remains unknown. Document exactly when completed negative evidence may set false. | SC-041, SC-042 |
| SC-044 | C | **Prove unknown risk still gates.** Exercise unknown/true/qualified-false with `reachable_only`. | Required failed analysis is operational failure. Optional permitted degradation keeps unknown threshold findings active; only qualified completed negatives can lower gating. | SC-043, SC-034 |
| SC-045 | F | **Scope reachability to module instances.** Review advisory-only matching across modules/packages/versions. | One reachable affected instance cannot mark unrelated instances assessed/unreachable. Multi-module fixtures retain analyzer scope and build context. | SC-043, SC-018 |
| SC-046 | F | **Record platform/build/test context.** Qualify tags, platform-specific files and test inclusion. | Analysis reports its selected context; unsupported targets remain unknown. Negative results from one build context cannot be reused for another. | SC-045 |
| SC-047 | F | **Add reachability provenance compatibly.** Keep nullable legacy field while recording analyzer/status/context. | Old decoding still works; new records distinguish missing tool, failed and unsupported analysis with version/time/context. | SC-004, SC-043 |
| SC-048 | F | **Reject incompatible tool protocols safely.** Validate completion/error message handling for supported govulncheck output. | Unknown protocol cannot create all-false results. Optional extra fields remain forward-compatible; supported versions have fixtures. | SC-041, SC-037 |
| SC-049 | F | **Prevent incomplete reachability reuse.** Audit any current or proposed cache/memoization. | Only complete context/version-qualified evidence reusable. Interrupted/stale negative results never persist as safe; if cache absent, document evidence and constraint. | SC-047, SC-048 |
| SC-050 | F | **Qualify with real pinned govulncheck.** Compare controlled reachable/imported-only/absent fixture cases. | Preserve redacted raw output, tool version and revision. Reconcile alias/symbol semantics; disagreement investigated rather than treated as majority-vote truth. | SC-043, SC-045, SC-095 |

## F — Baseline-ref integrity

Surfaces: `scanner/baseref.go`, `baseref_test.go`, engine outcomes, baseline/fingerprint tests and temporary worktree helpers. Preserve line-motion behavior without hiding incomplete analysis.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-051 | C | **Reproduce asymmetric scan failure.** Make fakes fail only at head or base while returning observations. | Tests show `ScannerRuns.Error` can coexist with nil engine error. Both asymmetries reject a valid delta and preserve available head evidence. | SC-002, SC-003 |
| SC-052 | C | **Validate both sides before subtraction.** Check required execution completeness before fingerprints suppress findings. | Partial/error/missing required base scanner is not valid baseline. Complete comparable scans still suppress old findings and retain genuinely new risk. | SC-051, SC-034 |
| SC-053 | C | **Check comparability and mutable scanner state.** Audit shared instances/config across head/base runs. | Relevant scanner sets/scope comparable; stateful fake does not leak rules/files/policy across revisions. Mismatch yields comparison error with head evidence. | SC-052 |
| SC-054 | C | **Bound cleanup and preserve caller state.** Cover failed scans, timeout and worktree operation failures. | Cleanup attempted with bounded context; failures visible. Caller HEAD/index/untracked files unchanged; deadline outcome documented, temporary registration not silently leaked. | SC-052, SC-053 |
| SC-055 | F | **Pin refs to commit IDs once.** Avoid mutable ref names changing mid-comparison. | Controlled ref movement cannot alter compared commits after resolution. Report exact identities; invalid/ambiguous ref fails without modifying checkout. | SC-054 |
| SC-056 | F | **Qualify subdirectory/monorepo scope.** Check relative paths and symlink resolution in comparison. | Root/subdirectory fixtures compare intended inputs once; outside-root unsupported scope rejected. No basename coincidence suppresses unrelated findings. | SC-053, SC-055 |
| SC-057 | F | **Reconcile layered suppression totals.** Review baseline, inline, VEX and ref filtering composition. | Original/remaining/suppressed counts reconcile with no double counting; each reason traceable. Filtered totals are not presented as raw observations. | SC-052, SC-076 |
| SC-058 | F | **Qualify comparison identity changes.** Cover package version, line motion, rename and changed rule ID. | Supported motion stays stable; distinct instances/rules do not disappear. Fingerprint changes have explicit migration/collision regressions. | SC-024, SC-052, SC-078 |
| SC-059 | F | **Fix diff edge-case decisions.** Investigate pure deletion, empty diff, no-file findings and unusual/renamed paths. | Table fixtures state intended keep/drop behavior; empty diff does not falsely establish global coverage. Path attribution remains deterministic. | SC-055, SC-061 |
| SC-060 | F | **Compare under compatible rule/DB snapshots.** Prevent mid-run advisory refresh from masquerading as code change. | Base/head share or record compatible evidence; controlled data change either rejected as incomparable or explicitly explained. | SC-053, SC-081 |

## G — Snapshots, coverage and analysis depth

Surfaces: `scanner/diff`, `engine.go`, scanner `types`, `filter`, `sast/goast_ssa.go`, `sbom` and CLI. All items in this epic are follow-up.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-061 | F | **Define actual staged-snapshot semantics.** Design read-only index content scanning. | Decision covers partial staging, deletion, mode, symlink, submodule and untracked behavior. No stash/reset that changes user work; unsupported cases explicit. | SC-003 |
| SC-062 | F | **Scan index bytes.** Implement snapshot with original repository path attribution. | Staged secret detected after unstaged removal; unstaged-only secret not called staged. Index/worktree unchanged; temporary data cleaned after failure. | SC-061 |
| SC-063 | F | **Cover staged special paths/entries.** Include whitespace/Unicode/newline names, renames and symlinks. | Git parsing cannot split paths or escape snapshot root. Unsupported entries visible; modes retained without executing repository files. | SC-062 |
| SC-064 | F | **Unify timeout cause across phases.** Audit collection, native/external execution and post-processing. | Actual CLI returns deadline `3` versus ordinary error `2` per contract. Partial findings survive safe paths; cleanup cannot hang indefinitely. | SC-036, SC-091 |
| SC-065 | F | **Account for excluded/unsupported inputs.** Add categories for explicit and built-in skips. | Fixture includes testdata/vendor/build/dist, large/unreadable and user-excluded files. Counts reconcile; required coverage can reject relevant omissions. | SC-004 |
| SC-066 | F | **Expose native SSA degradation.** Replace silent package-load/type-failure no-findings behavior with depth status. | Cold-cache/type-error/no-typed-root fixtures visible. Clean and tainted SQL/path/SSRF/shell controls work; required deep analysis cannot pass when absent. | SC-004, SC-065 |
| SC-067 | F | **Qualify result filtering versus scan scope.** Explain full analysis followed by diff filtering. | Cross-file source/sink change keeps needed context. No unsupported incremental-speed promise or full-backlog closure based on delta-only results. | SC-059, SC-066 |
| SC-068 | F | **Validate SBOM schemas and identifiers.** Check declared CycloneDX/SPDX output contracts. | Positive/empty/error outputs validate against pinned schemas; correct UUID syntax where required. Generation failure is not successful empty inventory. | SC-024 |
| SC-069 | F | **Make source SBOM discovery scope explicit.** Align recursive module discovery or declare root-only coverage. | Monorepo fixtures verify provenance and included modules. Root-only source collection never called whole-repo/artifact inventory. | SC-068, SC-018, SC-030 |
| SC-070 | F | **Qualify classification/archive coverage.** Trace renamed binary/archive input into selected checks. | Synthetic formats classified accurately; unsupported nesting visible; extraction limits retained. No implication artifacts are covered by `--all`. | SC-065, SC-068 |

## H — Suppression identity and retained evidence

Surfaces: `scanner/vex`, `fingerprint`, `suppress`, `internal/baseline`, reporters. Full organizational approval infrastructure is outside these technical repairs.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-071 | F | **Keep ecosystem/type in VEX matching.** Replace name-only identity with canonical supported products. | Same advisory/name/version in two ecosystems suppresses only intended one. Invalid/unsupported PURLs cannot broaden scope. | SC-003, SC-024 |
| SC-072 | F | **Qualify PURL encoding/namespace/qualifiers.** Decide which supported attributes affect identity. | Scoped npm/Maven/percent-encoded fixtures round-trip correctly. Identity-bearing qualifier/subpath cannot be discarded silently. | SC-071 |
| SC-073 | F | **Make broad VEX scope explicit.** Define product-free/versionless behavior under policy. | Strict mode rejects or explicitly authorizes broad statements; invalid products never become wildcard. Compatibility/migration examples documented. | SC-071, SC-072 |
| SC-074 | F | **Scope advisory alias suppression.** Match CVE/OSV/GHSA aliases within package evidence. | Alias suppresses intended affected instance only; unrelated/missing-identity findings stay active, ambiguity is visible. | SC-071 |
| SC-075 | F | **Qualify baseline expiry boundaries.** Review timezone, invalid dates and equality boundary. | Fixed-clock before/at/after tests; malformed/expired entry cannot silently suppress. Existing v1/v2 loading preserved or deliberately migrated. | SC-003 |
| SC-076 | F | **Retain suppressed observations and reasons.** Add audit-safe evidence without retaining raw secret values. | Baseline/inline/VEX/ref-suppressed identities recoverable with reasons; counts reconcile and default public output stays redacted. | SC-004, SC-071, SC-075 |
| SC-077 | F | **Qualify inline ignore scope.** Review wildcard, missing reason and directive in non-comment text. | Arbitrary literals cannot imply approved comment without documented behavior. Strict mode can reject reasonless/wildcard suppressions; legacy differences visible. | SC-076 |
| SC-078 | F | **Prevent fingerprint serialization/instance collisions.** Review delimiter keys and package identity. | Crafted delimiter-bearing fields cannot collide by serialization; version/location identity and line-motion have explicit compatibility tests. | SC-024, SC-003 |
| SC-079 | F | **Normalize paths safely across platforms.** Include absolute/separator/archive/temporary paths. | Different files never merge by normalization or escape root in suppression reads; temporary checkout paths not persisted as identity. | SC-078, SC-056 |
| SC-080 | F | **Expose exception authority limits.** Record source versus independently approved policy explicitly. | Repo-supplied metadata cannot imply independent approval. Provenance fixtures and docs state what remains unimplemented organizational governance. | SC-073, SC-076, SC-077 |

## I — Vulnerability data correctness

Surfaces: `internal/vulndb/{offline,version,osv,disk,cache,retry}.go`, `scanner/risk.go`, config/CLI. Ground truth comes from pinned synthetic snapshots; live advisory drift is separate evidence.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-081 | F | **Record DB snapshot provenance.** Carry source/acquisition time/support through lookup paths. | Report identifies data used, including cache/offline hits. File touch cannot masquerade as source refresh; supported ecosystems visible. | SC-004 |
| SC-082 | F | **Enforce offline freshness policy.** Preserve useful offline support while rejecting stale required evidence. | Fresh/stale/missing/corrupt fixtures follow policy; changing mtime cannot refresh data age. Actionable refresh diagnostics. | SC-081 |
| SC-083 | F | **Qualify ecosystem comparator support.** Replace unsupported generic-order confidence with explicit capability. | Pinned release/prerelease/postrelease/qualifier cases per ecosystem. Unsupported ordering errors or remains uncertain, never confidently clean. | SC-081 |
| SC-084 | F | **Expose unsupported GIT ranges.** Review ignored range types and explicit-version fallback. | GIT-only advisory cannot yield clean fully assessed package. Listed versions matched correctly; unsupported remainder visible. | SC-083 |
| SC-085 | F | **Test OSV interval boundaries.** Cover introduced/fixed/last-affected/limit, repeated intervals and withdrawals. | Exact boundary expectations from pinned fixtures; missing event support visible. Reordering valid inputs cannot create accidental clean match. | SC-083 |
| SC-086 | F | **Build online/offline parity tests.** Match identical package tuples against identical advisory data. | Equal matches for supported semantics; mismatches triaged individually. No live service required for correctness gate. | SC-083, SC-084, SC-085 |
| SC-087 | F | **Bound/atomize DB updates.** Qualify interrupted downloads/index writes, archive size and concurrent readers. | Last valid snapshot survives failures; partial index never called fresh. Test update locks, cleanup and resource limits. | SC-082, SC-086 |
| SC-088 | F | **Preserve batch query partial failures.** Audit retry exhaustion, response alignment and cancellation. | Safe successful matches retained; unassessed tuples/errors explicit. Other successful batches cannot hide required lookup failure. | SC-034, SC-081 |
| SC-089 | F | **Qualify KEV/EPSS completeness.** Review disabled, offline and failed enrichment with required policy. | Unknown KEV cannot pass required KEV decision. Optional degradation visible with source/time; absence does not become false by retry failure. | SC-081, SC-088 |
| SC-090 | F | **Isolate/version lookup caches.** Include relevant ecosystem/version/source/schema identity. | Different tuples/snapshots never share wrong answer; failures/partial answers not cached as clean. Corruption recovery explicit and race-tested. | SC-086, SC-088 |

## J — Integration proof and handoff

Surfaces: CLI/engine/integration tests, `pkg/api/exit.go`, `.github/workflows/ci.yml` and docs. Nine items are core; the performance harness is follow-up.

| ID | Scope | Assignment | Acceptance evidence | Depends on |
| --- | --- | --- | --- | --- |
| SC-091 | C | **Test actual CLI exits and reports.** Build binary once; run deterministic fixture/fake-tool cases. | Clean=`0`, gate=`1`, operational=`2`, deadline=`3`; capture stdout/stderr/report from same invocation, including findings plus failure. Do not reimplement gate in tests. | SC-014, SC-024, SC-034, SC-044, SC-054 |
| SC-092 | C | **Qualify timeout/error precedence.** Exercise collection, execution and comparison in repaired paths. | Required deadline not downgraded to `2` merely because engine returned a result. Preserve partial observations where safe; document unreportable paths. | SC-091 |
| SC-093 | C | **Exercise combined false-pass controls.** Compose operational faults, old debt and new threshold finding. | Crash, unknown reachability and incomplete base cannot yield valid pass or silently suppress head risk. Complete clean/finding controls also pass expected assertions. | SC-091, SC-092 |
| SC-094 | C | **Wire focused correctness into CI.** Reuse current workflow conventions and explicit suite selection. | Normal PR checks run core and built-CLI matrix; intentional regression fails job. Integration-tag cases invoked or moved into deterministic suite; live tooling separate. | SC-093 |
| SC-095 | C | **Publish real tool/command qualification.** Run supported commands in permitted environment or mark evidence missing. | Matrix records exact versions/args and observed clean/finding/error statuses for adapters/govulncheck. Fake checks distinct; unavailable versions remain unqualified. | SC-031, SC-043, SC-094 |
| SC-096 | F | **Build repeatable resource budgets.** Measure representative Go/npm fixture cold/warm behavior. | Named runner/input sizes, wall time/RSS/concurrency and agreed non-flaky budget. Secrets-only microbenchmark not presented as full SAST/monorepo proof. | SC-094, SC-066 |
| SC-097 | C | **Document corrected semantics and migration.** Explain changed inventory/findings, fallback and comparison errors. | Before/after examples for old sums, multi-version npm, tool failure and bad baseline; API/fingerprint/baseline implications explicit, no blanket regeneration. | SC-014, SC-024, SC-034, SC-044, SC-054 |
| SC-098 | C | **Test leakage in new error paths.** Seed synthetic sensitive markers in tool/parser/comparison diagnostics. | Raw markers absent from affected public reports/logs/comments. Retain useful bounded reasons; do not weaken redaction to update expected output. | SC-091, SC-092 |
| SC-099 | C | **Produce exact-head acceptance report.** Run integrated checks and summarize evidence individually. | Revision/PRs/core IDs/results/expected findings recorded. Focused tests, race, vet, integration-tag and affected helper checks complete or explicitly blocked; hosted/real-tool evidence separate. | SC-094, SC-095, SC-097, SC-098 |
| SC-100 | C | **Reconcile delivery and prepare next assignment.** Review core outcomes against original risks. | Every core ID evidenced or explicitly incomplete. Next coherent follow-up batch/dependencies selected; unresolved VEX/coverage/policy/consumer risks prevent unsupported readiness claim. | SC-099 |

## Assignment and closure template

No external issues are created by this package. When assigning later, use:

```text
ID / title:
Owner / scope / priority:
Starting revision and affected code/tests:
Source finding / invariant:
Dependencies:
Reproducer and observed current behavior:
Required behavior / implementation boundary:
Positive, negative and adverse acceptance cases:
Compatibility / migration:
PR / final revision:
Focused commands and results:
Broader / external checks pending:
Remaining limitations and next IDs:
```

Follow dependency edges rather than numeric order alone. After the core, prioritize VEX identity (SC-071–074), explicit outcome/coverage (SC-004–006, SC-065–066), staged integrity (SC-061–064) and data support/freshness (SC-081–090) according to the pilot's required surfaces. Resource bounds and deeper resolution remain prerequisites for their larger support claims.

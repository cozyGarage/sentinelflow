# Delivery plan: trusted CI gate to continuous feedback

Status: proposed backlog, 2026-10-17. Grounded in the [readiness findings](organizational-readiness.md) and [target design](devsecops-design.md). Sprint scope is planning guidance, not a commitment that enterprise readiness follows automatically from a date or feature count.

Assume two engineers, part-time AppSec/platform review, and two-week sprints. Six sprints are roughly twelve weeks at that staffing; a solo maintainer should expect a longer sequence and split work at acceptance boundaries. Reserve approximately 25% capacity for validation, pilot feedback and unexpected defects. If acceptance does not fit, move scope rather than weakening a trust gate. No work below is marked implemented by this document.

## Milestones and dependencies

| Sprint | Outcome | Depends on | Adoption boundary |
| --- | --- | --- | --- |
| 1 | Correct inventory and honest tool completion | Usable test environment | Advisory pilot only. |
| 2 | Qualified CI, exception and report contracts | Sprint 1 execution semantics | Selected mandatory-gate candidate. |
| 3 | Versioned evidence and protected policy | Sprints 1–2 | Controlled mandatory-gate pilot. |
| 4 | Owned, durable finding feedback | Sprint 3 identity/schema | Team remediation pilot. |
| 5 | Deployed-SBOM continuous assessment | Sprints 3–4 and deployment identity | First shift-right milestone. |
| 6 | Staging/runtime feedback and rollout qualification | Sprint 5 inventory, prior quality evidence | Broader rollout only if acceptance passes. |

A late runtime integration must not delay a useful trustworthy CI release. Conversely, shipping six sprint branches is not evidence of organizational acceptance.

## Sprint 1 — Package truth and execution truth

Assignment-ready breakdown: [14-day plan and 100-item scan-correctness backlog](sprint/README.md). The timeboxed core repairs F01–F03; follow-up items cover the remaining scan-correctness boundaries.

Goal: no clean or reduced-risk conclusion from incorrect package versions or incomplete tools. Addresses F01–F03 and the reachability part of F06.

| Work item | Existing surfaces | Acceptance evidence |
| --- | --- | --- |
| S1.1 Resolved inventory semantics | `dependencies/scanner.go`, `lockfiles.go`, SBOM parser reuse | Failing-first fixtures for multiple full Go checksum versions, `replace`, missing sums, workspace boundaries, nested npm v1 and same-name/multi-version npm/Yarn. Preserve every distinct package instance/version; historical checksums never overwrite selected versions. Document declared/locked/resolved fallback. |
| S1.2 Per-tool completion | `adapter/external` | Fixtures/fake executables cover accepted finding exits, tool-error exits with findings, malformed/truncated output, timeout, missing tool and required/optional modes. Preserve findings and errors together; required failures never pass. |
| S1.3 Reachability integrity | `dependencies/reachability.go` | JSON preamble followed by nonzero tool failure remains unknown/error. Match only with complete supported output and aliases. `reachable_only` cannot lower risk from incomplete evidence. |
| S1.4 Baseline-ref completeness | `scanner/baseref.go`, engine runs | Head/base failures and mismatched required coverage yield indeterminate comparison; neither is silently used as a valid baseline. Successful comparable runs still suppress pre-existing observations. |

Demo: a fixture with two installed lodash versions retains both; a fake scanner emits a finding then crashes; a baseline scanner fails only at the base revision. Show correct inventory, retained evidence and non-pass outcomes.

Required checks: restore writable test/cache capacity without deleting unrelated data; run focused new regressions, `go test -race ./...`, and `go vet ./...`. Add deterministic parser tests over repeated input/map order. Treat network advisory lookups as mock-backed tests here; run live smoke tests separately.

Exit: F01–F03 repaired for the chosen Go/npm profile and no failure-injection false passes. Record exact commit, commands and outcomes. If not complete, do not promote mandatory gating.

## Sprint 2 — CI and suppression contracts teams can trust

Goal: qualified outputs, precise snapshots, bounded exceptions and reproducible delivery. Addresses F04–F07. This is intentionally a high-risk sprint; split into two iterations if needed.

| Work item | Change | Acceptance evidence |
| --- | --- | --- |
| S2.1 VEX identity and authority | Preserve canonical PURL ecosystem/version/qualifiers as needed; reject ambiguous/global scope unless explicitly authorized | Same-name packages in different ecosystems never cross-suppress. Invalid products cannot widen scope. Expired/unapproved statements remain visible. Existing legitimate VEX fixture compatibility is documented. |
| S2.2 Report qualification | GitLab schema-correct SAST/dependency output; correct empty lists/status/severity/location; JUnit and annotation corrections; SBOM schema/subject qualification (F11) | Validate positive/empty/error reports against pinned declared schemas, including CycloneDX/SPDX. Correct UUID identifiers, make monorepo scope explicit, and distinguish source from artifact-observed SBOMs. Assert JUnit counts match testcases, tool errors are distinguishable and policy semantics are documented. Escape adversarial paths/titles in workflow annotations. |
| S2.3 Snapshot/exit contract | Scan the actual staged snapshot; end-to-end timeout and report behavior; missing report is unknown | Partially staged secret fixture cannot pass by editing only the working tree. Collection/adapter/reporter phase failures yield documented exits and best available partial evidence. No-report Action output never advertises a known zero. |
| S2.4 CI consumer qualification | Separate GitLab report production from gate; GitHub pinned release/version install; fork-safe comments and upload | External consumer repo: clean `0`, finding `1`, scanner `2`, timeout `3`; reports retained on all possible paths. GitLab UI ingestion confirmed on named version/tier. Read-only fork PR works without secrets; optional comments degrade visibly. |
| S2.5 Release ordering/verification | Stage release until signatures, provenance, SBOM and required scans exist; verify expected signer identity | Tampered bytes, wrong signer and missing bundle fail install verification. No stable release published after failed required checks. Consumer runs the exact built digest. Explicit policy for genuine self-scan findings. |

Demo: one GitHub PR and one GitLab MR display expected findings; the gate blocks while ingestion succeeds. A tampered release fails installation. A cross-ecosystem VEX fixture fails to suppress the wrong package.

Exit: supported consumer matrix published with tested tool versions/platforms and exact evidence links. “Schema-valid locally” and “ingested by hosted product” are separate checklist entries. If GitLab access is unavailable, keep GitLab experimental and proceed with a GitHub-only qualified profile.

## Sprint 3 — Evidence contract and protected decisions

Goal: independently explain and reproduce every gate. Addresses F04/F06/F09 policy and identity gaps.

| Work item | Change | Acceptance evidence |
| --- | --- | --- |
| S3.1 Versioned evidence | Extend API with subject, inventory provenance, scanner status, coverage, rule/DB versions and decision records | JSON schema/golden fixtures; old consumer compatibility or explicit migration. Serialize scanner errors and simultaneous findings without losing either. |
| S3.2 Protected profile | Resolve trusted policy independently of scanned branch; enforce mandatory scanners, exclusion ceilings, freshness and exception authorities | PR disabling scanner, weakening threshold, widening exclusion or adding wildcard suppression cannot weaken the protected gate. Effective policy/hash visible in report. |
| S3.3 Pure decision evaluator | Extract current conditions into an evaluator; retain public exit codes and add reasons | Table tests cover precedence, incomplete evidence, disabled enrichment plus required KEV, unknown reachability, stale DB and exception expiry. Evaluator consumes saved evidence without rescanning. |
| S3.4 Coverage and DB freshness | Required/optional/not-applicable statuses; explicit built-in exclusions; SSA degradation; snapshot age/support (F06/F11) | No applicable input differs from missing required tool. SSA load/type failures are visible rather than silently complete. Unsupported inventory/range semantics cannot pass as fully assessed. Online/offline parity fixtures include ecosystem-specific ordering and unsupported GIT ranges; stale/corrupt/missing database follows profile policy. |
| S3.5 Evidence security | Redaction, bounded diagnostics, storage/retention guide and fork trust model | Seeded sensitive values absent from JSON/SARIF/JUnit/HTML/comment/log outputs. Invalid artifact provenance/path/size rejected before privileged processing. |

Demo: the same stored evidence yields the same decision with the same policy hash. A malicious configuration change cannot remove mandatory checks. A stale database produces a visible operational decision.

Exit: choose two or three repos, owners and rollback contacts; enable only the supported blocking profile after an advisory baseline week. No blanket organization rollout.

## Sprint 4 — Close the remediation loop

Goal: one owned lifecycle case with reliable delivery instead of repeated report noise. Addresses F09.

Choose one backend in the first two days: DefectDojo if normalized case history dominates; Dependency-Track if SBOM portfolio analysis dominates. Qualify actual import/parser/API behavior. Add the second only after the first is complete; do not build a dashboard or generic integration marketplace.

| Work item | Change | Acceptance evidence |
| --- | --- | --- |
| S4.1 Ownership and exceptions | Service catalog/CODEOWNERS mapping, unowned queue, approved expiring exceptions | Every blocking case routes to an owner or visible fallback. Reason, approver and expiry are reviewable. Expiry reactivates risk without duplicate cases. |
| S4.2 Idempotent exporter | Durable delivery manifest in retained storage; scoped backend mapping | Import same report repeatedly, retry after timeout/429, interrupt after remote acceptance, then replay. One lifecycle record per intended case, visible delivery state and replay instructions. |
| S4.3 Closure/reopen semantics | Comparable full-scope scan is authoritative; preserve triage | Partial scan, missing tool, PR-only scan and changed rule coverage cannot auto-close debt. Complete fixed scan closes; recurrence reopens; independently accepted risk stays auditable. |
| S4.4 Developer feedback | Explain new/existing/accepted risk, owner, remediation and exact decision | Sticky PR comment links stable evidence/case; comments do not become the only evidence store. A reviewer can identify why the gate failed without reading raw logs. |

Demo: finding → owned case → fix → verified closure → recurrence → reopen. Repeat with export outage and replay, and with a partial scan that must not close anything.

Exit: backend ingestion/closure confirmed against named backend version, credentials scoped, operational retry/backup/retention ownership assigned, and duplicate behavior measured. Pilot metrics have denominators and adjudication notes.

## Sprint 5 — Continuous assessment of what is deployed

Goal: detect newly disclosed risk without requiring a code change. First shift-right delivery; extends existing SBOM ingestion and offline/online matching.

| Work item | Change | Acceptance evidence |
| --- | --- | --- |
| S5.1 Deployment inventory | Import digest/release/service/environment/owner/SBOM mapping from the pilot deployment system | Deploy/update/rollback/retire fixtures retain correct active digests. Mutable tags cannot overwrite identity. Orphaned/missing SBOMs create coverage alerts. |
| S5.2 Scheduled matching | CI scheduler or existing scheduler rescans retained SBOMs with fresh advisory snapshot | Introduce a mocked new advisory after deployment with no git change. Produce exactly one owned case for affected active release and link original provenance. |
| S5.3 Risk and freshness policy | Enrichment age/source, reachability uncertainty, SLA routing | New KEV/critical risk routes under explicit policy. Offline gaps or advisory refresh failures alert operationally; unknown never becomes safe. |
| S5.4 Safe reconciliation | Separate fixed code, replaced deployment and retired asset states | Replacing one of two deployed old releases does not close the other's risk. Rollback reactivates relevant exposure. Retired asset retention follows policy. |

Demo: Monday release, Wednesday advisory, same commit/digest; alert reaches owner, patch deploys, remaining old deployments stay tracked until retirement.

Exit: active deployed inventory coverage and alert latency measured for the pilot; proposed target is complete scheduled matching within 24 hours. No claim of runtime behavior detection yet.

## Sprint 6 — Staging/runtime context and rollout proof

Goal: demonstrate feedback from running software to developer regression coverage while proving the supported operating envelope.

| Work item | Change | Acceptance evidence |
| --- | --- | --- |
| S6.1 Staging DAST | One ZAP baseline adapter/import with authorized target and explicit auth/scope/time limits | Positive/negative fixtures and one staging run; error vs finding exits; missing auth/coverage visible. Do not describe passive checks as full active/API testing. |
| S6.2 Runtime correlation | One Falco sink/event-file import using existing infrastructure | Replayed events correlate to deployment digest/owner, deduplicate by event identity and retain unmatched events. No runtime silence suppresses SCA findings. |
| S6.3 Regression feedback | Convert one staging/runtime incident into a source/config/test regression fixture | Demonstrate event → owned action → fix PR → regression test → release evidence. No automated production response required. |
| S6.4 Quality/performance gates | Expanded corpus, scheduled fuzz, integration-tag CI, representative performance fixtures | All blocking rules have reviewed positive/negative/adversarial cases. Per-category metrics/sample sizes; no aggregate score hides unsupported surfaces. Report wall time/RSS cold and warm on named hardware. |
| S6.5 Rollout and operations | Canary profiles, compatibility policy, troubleshooting and rollback runbooks | Operator drills database outage, bad policy update, scanner upgrade, export outage and revoked signer. Roll back to last known policy/tool versions without losing evidence. |

Proposed pilot targets: zero false passes in fault tests; ≥95% adjudicated precision for blocking profile with sample size; PR p95 added time ≤3 minutes on documented 2-vCPU/8-GiB fixture runner; all cases owned or in a monitored unowned queue; no duplicate cases after retry; no closures from partial scans. Calibrate latency/performance after measurement, not by weakening correctness.

Exit: publish an acceptance report containing supported versions/profiles, exact revisions, local checks, hosted checks, staging/runtime evidence, pilot metrics and open limitations. If runtime access is unavailable, ship qualified CI/SBOM continuous assessment and leave runtime integration explicitly experimental.

## Release and rollout checklist

Each sprint delivers small scoped PRs: failing regression for a concrete defect, implementation, compatibility/docs and exact-head validation. Do not combine the whole roadmap into a refactor. Run independent tests in separate caches when needed; avoid modifying the same build/test artifacts concurrently.

- Advisory: baseline noise, coverage and performance on representative repositories; inspect findings rather than optimizing for an empty self-scan.
- Canary gate: one team/profile, protected policy and required completeness, monitored fallback/exception process.
- Supported gate: hosted consumer and release verification completed; ownership, retention and replay operated by named people.
- Organization expansion: template rollout with version pinning and rollback; add languages/platforms only when their qualification matrix passes.
- Shift-right: deployed digest/SBOM coverage first, then runtime correlation with an incident-to-regression demonstration.

## Start here

The next implementation task is **S1.1–S1.4**, after restoring test capacity. Do not start with a new dashboard, new scanner category or AI feature. The review has sufficient source evidence to prioritize these repairs, but it has not executed their reproducer tests or validated a new build. Keep that boundary visible in the implementation handoff.

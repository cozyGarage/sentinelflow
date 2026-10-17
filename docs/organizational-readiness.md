# Organizational CI/CD readiness review

Review date: 2026-10-17. Source revision: `cdd7cd7c390c65809fcd08e10dd0492360579565`.
Status: source audit and proposed delivery plan; no new product capabilities shipped by this review.

Read this assessment first, then the [target design](devsecops-design.md) and [sprint plan](devsecops-sprints.md). These documents define the proposed next phase after the historical R0–R6 roadmap.

## Verdict and product direction

SentinelFlow has a credible local-first security scanning foundation and can be evaluated in an advisory CI pilot. It is not yet evidenced as an organization-wide mandatory security gate or a complete shift-left/shift-right feedback system. “Not ready” needs this qualification: existing functionality is substantial, but several paths can misstate coverage or package identity, and there is no persistent remediation or deployed-asset lifecycle.

The strongest positioning is **a portable security evidence and policy gate that connects developer workflows, specialist scanners, release artifacts, and remediation systems**. Keep the single binary and useful native checks. Invest differentiation in trustworthy execution, explainable decisions, integration contracts, and closing the feedback loop. Building a broader collection of shallow detectors will make that harder to deliver.

Suggested initial customers are small platform/AppSec teams supporting Go and JavaScript services on GitHub Actions, with GitLab as a separately qualified integration. Start with two or three representative repositories and one deployment environment. This is a proposed focus, not evidence about existing users.

## Review boundaries

Inspected the CLI, scanner engine, dependency parsers, external adapters, baselines, fingerprints, diff filtering, VEX, reachability, report formats, quality corpus, Action, CI/release workflows, and current documentation. Compared patterns against primary documentation from established open-source projects below.

Fresh `go test -race ./...` was attempted with the existing temporary integration caches. It stopped at setup with `disk quota exceeded`; no packages were validated by that invocation. Sandbox startup also failed on a `/tmp/.git` mount quota error. Source reads proceeded outside that sandbox. This is an environment limitation, not a demonstrated test failure in the product. No hosted CI results, release downloads, signature verification, real GitLab ingestion, runtime deployment, or organization pilot were verified in this review. Existing test files and workflow definitions are evidence of intended checks, not fresh passing results.

Historical notes flagged an `x/net` self-scan discrepancy. The current checksum file contains the full-module `v0.61.0` entry, not the old full-module `v0.58.0` entry. The historical result must not be reported as a current vulnerability finding; the underlying first-version parser behavior still exists.

## Existing work worth preserving

| Capability | Current evidence | Qualification |
| --- | --- | --- |
| Portable gate | `pkg/api/exit.go`, `internal/cli/scan.go` | Exit constants distinguish pass/findings/tool/timeout; audit timeout paths below. |
| Developer feedback | `action.yml`, `scripts/pr-comment.sh`, `internal/reporter/ci.go` | Sticky comments, summary, annotations, counts, and several report formats exist. |
| Debt and change handling | `internal/baseline`, `internal/scanner/{fingerprint,diff,baseref,suppress}` | v2 baseline reason/expiry support, line-independent fingerprints, inline suppression, staged/diff/ref modes already exist. |
| Multiple analysis surfaces | `internal/scanner`, `internal/adapter` | Native secrets/IaC/SAST/dependencies/policy plus optional tools, artifact and container paths. `--all` deliberately excludes artifact, license, and container scanning. |
| Native Go dataflow | `internal/scanner/sast/goast_ssa.go` | Selected shell, SQL, filesystem and outbound HTTP sinks already have SSA taint analysis. Extend and qualify this work rather than scheduling it as missing. |
| Vulnerability operations | `internal/vulndb`, `internal/scanner/{vex,risk.go}` | Batch OSV queries, retry/cache, offline indexes, risk enrichment and OpenVEX are implemented. |
| Supply-chain delivery | `.github/workflows/release.yml`, `.goreleaser.yml`, `scripts/install.sh` | Binary checksums, keyless checksum signing, provenance step, SBOM output and artifact self-scan are defined. Verification and publication ordering still matter. |
| Regression foundation | scanner/reporter tests, fuzz targets, `.github/workflows/ci.yml` | Race CI, SARIF schema/golden checks and parser tests exist. Integration build tag and corpus limitations remain. |

Do not schedule these entire capabilities as new work. Extend or repair their contracts.

## Prioritized findings

Priorities describe adoption risk and sequencing, not CVSS vulnerability ratings. **P0** blocks trusting mandatory decisions; **P1** blocks a supported integration or safe organizational rollout; **P2** improves usability and scale. Source findings below are code-path observations; acceptance tests are specified in the sprint plan and have not been run here.

### F01 — P0: dependency inventory is not reliably the resolved inventory

In [`GoModScanner.Scan`](../internal/scanner/dependencies/scanner.go), the `go.sum` overlay replaces versions parsed from `go.mod`. `parseGoSum` keeps the first full-module version per name. A checksum file can contain historical versions, so this can invent exposure or miss the selected vulnerable version. `replace`, workspaces and build context need explicit semantics; a checksum entry is not proof of deployment.

`parseNpmLock` and classic Yarn parsing deduplicate by package name. A project with two installed versions can lose one; npm map iteration can affect which version survives. The npm v1 fallback reads top-level dependencies without recursive nested traversal. This compromises SCA and any SBOM generated from the same parsers.

**Approach:** separate declared, locked, resolved and artifact-observed inventory. Preserve ecosystem/name/version/location identity. Use Go module-aware parsing and an explicit, controlled resolved-graph mode; never silently substitute historical checksums. Add old/new version, nested npm, replacements, workspace and no-network fixtures before implementation.

### F02 — P0: partial tool output can be promoted to successful analysis

[`external.Adapter.Scan`](../internal/adapter/external/external.go) returns success on a command error whenever parsed findings are non-empty. A crash, timeout or tool-specific error can therefore lose its failure status. A single rule for all scanner exit codes is insufficient.

[`govulncheckCalled`](../internal/scanner/dependencies/reachability.go) rejects a command failure only when it decoded zero messages. Valid preliminary JSON followed by failure can be treated as a complete run; unmatched findings then receive `Reachable=false`. With `fail_on.reachable_only`, that can reduce gating on incomplete evidence.

**Approach:** tool-specific accepted exits, completion/error parsing, bounded output and execution; retain findings alongside failure. Unknown reachability must remain unknown. Every mandatory scanner must produce positive completion evidence.

### F03 — P0: comparison scans can lose base-side errors

[`scanAtRef`](../internal/scanner/baseref.go) checks the error returned by `sub.Scan`, then returns only `res.Findings`. The engine normally records individual scanner failures in `ScannerRuns` rather than returning them. A partially failed base scan can therefore influence the “new findings” decision without a comparison completeness signal. Both base and head must be valid and comparable; asymmetric scanning can produce misleading deltas in either direction.

### F04 — P0: suppression trust boundaries need stronger identity and governance

[`vex.parsePURL`](../internal/scanner/vex/vex.go) discards the package type, qualifiers and subpath; matching uses name and optional version. The same advisory and package name in different ecosystems can be suppressed across that boundary. Product-free statements are global. Author/trust policy, approval and expiry are not enforced by this parser.

Inline suppressions accept `*`/`all` and do not require a reason. Baselines support reasons/expiry, but repository-controlled exceptions alone do not establish independent approval. The scanned branch can also change configuration, policy and scanner enablement.

**Approach:** canonical ecosystem-aware identities, explicit allowed VEX scope, bounded exception lifetime, and a protected organization policy that repository changes cannot weaken. Keep suppressed observations for audit rather than only aggregate counts.

### F05 — P1: report serialization is ahead of consumer qualification

[`GitLabSASTFormatter`](../internal/reporter/ci.go) emits `location.start.line`/`end.line`, uppercased severity strings, nullable empty vulnerability lists, and `scan.status=success` regardless of scanner errors. The dependency formatter lacks a structured dependency location. Existing tests inspect content; they do not validate both GitLab formats against the declared schemas. Treat these as integration defects to qualify, not an established supported GitLab contract. GitLab requires reports to validate against their declared version ([integration contract](https://docs.gitlab.com/development/integrations/secure/)).

The root README assigns SARIF to `artifacts:reports:sast`, which expects the native SAST JSON contract. Current GitLab also documents a distinct SARIF ingestion path, whose availability must be checked against the customer's version/tier. Security report ingestion depends on a successful producer job; preserving a failed scan's artifact alone does not prove ingestion ([report behavior](https://docs.gitlab.com/ci/yaml/artifacts_reports/)). Separate report production from the policy gate.

JUnit writes `tests=0` but one testcase for no findings; it serializes every finding as a failure independent of the actual policy decision. It is a security-results projection, not proof of application test execution. Annotations also need workflow-command escaping for untrusted paths and fields. Action `findings-count=0` when no report exists should be “unknown/error,” not a clean-looking count.

### F06 — P1: scan completion and coverage are under-specified

The engine records warnings and skipped oversized/unreadable files, which is useful. However, built-in exclusions such as `testdata`, `vendor`, `build`, and `dist` do not provide a complete machine-readable coverage inventory. Optional adapters receive their own root-based commands rather than a uniform file scope. `--diff-base` filters results after full scanning, so it is not inherently a fast incremental scan. Staged filtering selects index changes but source scanners read working-tree files, so partially staged edits require an index-snapshot contract.

Native SSA already covers selected SQL, path and SSRF sinks as well as shell flows. However, `scanGoTaintSSA` returns no findings on package-load failure or no eligible typed roots without exposing an analysis-status record. A cold dependency cache, unsupported build context or type errors can silently reduce depth. Surface that degradation separately from a completed analysis with no matches.

Timeout mapping in the CLI checks context when `Engine.Scan` returns an error. If the engine instead returns a result containing scanner timeout errors, the later path returns tool exit `2`. Collect-time failures can also produce no report. The public four-exit contract needs end-to-end tests for each phase and partial-report behavior.

### F07 — P1: release publication does not wait for final evidence

GoReleaser publishes before checksum signing, provenance, SBOM and binary self-scan steps. A later failure can leave an already published release with missing assurance assets. The self-scan explicitly accepts finding exit `1` at the critical threshold. This is advisory self-inspection, not a critical-finding release gate.

Checksums verify byte integrity relative to a downloaded checksum file; they do not independently authenticate the publisher. Installer/Action consumer verification, including expected signer/workflow identity, is a separate acceptance requirement. SHA-pinning the Action also needs a deliberately pinned `version`: the install logic otherwise treats an unfamiliar action ref as a release version.

### F08 — P1: quality evidence cannot support broad detector claims yet

The labeled corpus has three positive labels across secrets and SAST. It aggregates by scanner/rule/file, so multiple occurrences collapse. “Clean” handling relies on fixture basenames; explicit negative labels are not a complete evaluation contract. This is a useful smoke test, not a representative precision/recall study.

Race tests and SARIF schema tests are present. `test/integration_test.go` requires the `integration` tag, which the normal `go test -race ./...` workflow does not enable. No current Makefile target enforces the performance budget described in the historical roadmap. Add a realistic corpus, negative and adversarial cases, per-rule counts, consumer-schema validation and measured resource budgets.

### F09 — P1 for shift-right: scans have no deployed-asset lifecycle

The current API carries git metadata and scanner results, but no durable service/release/digest/environment deployment inventory or finding history. Scheduled advisory changes, deployed asset retirement, owner/SLA state and runtime-alert correlation are not implemented as a product flow. SBOM rescanning is a foundation; it becomes shift-right only when it targets software still deployed and produces owned action.

### F10 — P2: documentation can overstate completed proof

The roadmap marks R2–R6 shipped, while acceptance evidence varies. Residual notes still say no offline mode and unsupported Gradle, although offline code and Gradle lockfile parsing exist. Retain the history, but distinguish implemented, locally validated, hosted validated and pilot accepted. A green self-scan is not a quality target by itself; expected real findings must remain visible.

### F11 — P1: SBOM and offline matching need independent qualification

[`sbom.Generate`](../internal/scanner/sbom/scanner.go) labels output CycloneDX 1.5, but constructs its serial number as `urn:uuid:sentinelflow-<timestamp>` rather than a UUID. It calls root-directory `dependencies.Collect`; unlike the engine's recursive manifest discovery, this does not establish a whole-monorepo inventory. Release SBOM generation invokes the source-oriented command from the checkout, which is not proof of the contents of every published binary or image. Validate CycloneDX/SPDX against their declared schemas and distinguish source inventory from artifact-observed inventory before portfolio ingestion.

[`vulndb/version.go`](../internal/vulndb/version.go) uses a generic segment comparator for ecosystem ranges and explicitly notes that full ecosystem qualifier ordering is not implemented. Offline matching also skips GIT ranges. Existing offline support is valuable, but unsupported comparisons must be declared or rejected rather than assumed equivalent to online matching. Qualify each ecosystem separately; a Go/npm pilot must not imply full Maven/PyPI offline correctness.

## Readiness by adoption scope

| Scope | Assessment at this revision | Exit condition |
| --- | --- | --- |
| Local developer experiments | Useful now, with documented detector limits | Reproducible install and meaningful feedback on the team's stack. |
| Advisory CI pilot | Reasonable next step | Preserve native outputs; inspect errors/skips; do not make SentinelFlow the sole mandatory decision source. |
| Mandatory gates on selected repos | Hold pending trust repairs | F01–F04 fixed with regression tests; F05–F08 qualified for the selected integration/profile. |
| Organization rollout | Not evidenced | Protected policy, owner/exception lifecycle, supported scanner matrix, pilot outcomes and operational runbooks. |
| Continuous production feedback | Design phase | Deployed inventory, scheduled rescans, reliable lifecycle delivery; runtime correlation is a later explicit milestone. |

## Open-source inspiration: borrow the contracts

These are design references, not head-to-head detector benchmarks. No comparative scans were run. Each recommendation below is an inference from the linked project documentation and this source audit. Open-source engines must be distinguished from vendors' hosted/commercial features; verify licenses and rule-pack redistribution rights before bundling.

| Project | Relevant pattern | Application to SentinelFlow |
| --- | --- | --- |
| [Trivy](https://trivy.dev/docs/latest/configuration/others/) | Deliberate CI exit configuration and scan controls | Make the effective profile, scanner completion and decision explicit. Keep the existing Trivy integration; qualify its exit and version contracts. |
| [Semgrep Community Edition](https://docs.semgrep.dev/deployment/oss-deployment) | A specialist code engine that can run in CI | Improve the existing adapter and rule evaluation. Do not promise hosted triage or commercial analysis from installing CE. |
| [Syft and Grype](https://oss.anchore.com/docs/projects/) | Separate inventory evidence from vulnerability analysis | Reuse SBOMs for new-advisory rescans and preserve cataloger provenance. Do not repeatedly rebuild an artifact just to rematch advisories. |
| [DefectDojo reimport](https://docs.defectdojo.com/import_data/import_intro/reimport/) | Repeated imports update, close or reactivate findings with explicit scope | Export idempotently to a qualified existing lifecycle system first. Never close findings from partial or PR-only scans. Do not assume a SentinelFlow parser already exists. |
| [Dependency-Track](https://docs.dependencytrack.org/getting-started/recurring-tasks/) | Recurring vulnerability analysis of a component portfolio | Use it as an optional SBOM analysis backend; correlate its project/version to deployed digest and owner. |
| [ZAP](https://www.zaproxy.org/docs/docker/baseline-scan/) | A bounded spider plus passive checks against a running target | Add staging DAST through an adapter/import after gate correctness. Passive baseline is not full active/API coverage. |
| [Falco](https://falco.org/docs/) | Runtime events enriched with workload context | Consume events through an existing sink; correlate to deployment identities. Building a kernel sensor is outside this plan. |

## Recommended investment order

1. Repair package truth, tool completion, comparison and suppression boundaries.
2. Qualify one complete developer workflow and one release workflow, including adverse cases.
3. Introduce a durable evidence/decision contract and controlled exception policy.
4. Connect findings to an existing remediation backend with idempotent delivery and verified closure.
5. Rescan deployed SBOMs on a schedule, then add staging DAST and runtime context.
6. Expand organizational adoption only after pilot metrics meet agreed targets.

Keep AI review, additional ecosystems, a hosted dashboard, custom runtime sensors, full CSPM and automatic production remediation outside the initial critical path. The next release should earn trust on a narrow supported profile before expanding feature breadth.

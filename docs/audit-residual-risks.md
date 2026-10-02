# Audit residual risks (post v1.2.0)

> Quality waves A–E, sprint Q1–Q3, residual sprint, and dead-code cleanups are on `main`. R2–R6 close the CI-gate and artifact gaps listed below. Rows that still apply after a train should stay; landed items move to “Landed”.

Re-audit after each release train. Unit tests green; `make demo` fails the gate as expected on intentional findings.

## Residual risks

| Area | Risk | Notes |
| --- | --- | --- |
| Exit codes | Historically a single `1` for findings, crashes, and timeouts | R2: `0` pass, `1` gate, `2` error, `3` timeout. Older wrappers that treat any non-zero as “vulns found” should distinguish `2`/`3`. |
| Fingerprints / baseline | v1 hashes included `StartLine`/`StartCol` — code motion reopened debt | R2: v2 fingerprints omit line numbers; v1 files still load. Migrate with `sentinelflow baseline`. |
| Detached HEAD metadata | `refs/heads/` only — empty `git_commit` on GitHub PR checkouts | R2: `git rev-parse` + `GITHUB_SHA` / `CI_COMMIT_SHA`. |
| Silent size skips | Engine 5 MB + secrets 1 MB + `dist/`/`build/` with no warning | R2: warnings + `scanners.max_file_size`. Artifact dirs go to the artifacts scanner (R5), not source scanners. |
| SARIF | Missing `partialFingerprints`, `security-severity`, CWE, invocations | R2: GitHub code scanning fields + schema tests. |
| Action pins / delivery | Floating tags; default image `:latest` unpublished | R3: SHA pins; `delivery: release` verifies `checksums.txt`; version-tagged default image. |
| Docker Hub | Images not published yet | Binaries + `delivery: release` / `build` first. Hub needs `DOCKER_USERNAME` / `DOCKER_PASSWORD`. |
| Module path | `go install` unsupported by decision | Module `github.com/cozygarage/sentinelflow` ≠ repo `cozyGarage/sentielflow`. |
| License scanner | High FN rate by design | Uses npm lockfile metadata when present plus a small hardcoded map. **Honesty path:** opt-in only (not in `--all`). |
| Dependencies | Bare Gemfile / Gradle still unsupported | Lockfile-first; `Gemfile.lock` supported. Go transitives via `go.sum` (R4). |
| OSV / network | Transport flake; was memory-only cache, no retry | Default `fail_on_error: true`. R4: querybatch, retry, 24h disk cache (`SENTINELFLOW_CACHE_DIR`). No offline/air-gapped mode yet. |
| SAST | Regex-first; Go SSA covers selected shell flows | Other source/sink families and dynamic dispatch remain uncovered. Semgrep adapter when installed (`mode: auto`). |
| Artifacts | Built outputs were never scanned | R5: classifier + unpacker + catalogers; `--artifacts` opt-in (not in `--all`). |
| Malware heuristics | Heuristic, not a sandbox | Opt-in, confidence-scored. No dynamic detonation (non-goal). |
| Secrets git history | Requires local `git` | Errors surface; `--diff-base` limits PR history to `base..head`. |
| Container delivery | Host Trivy needed for `scan-container` | `delivery: build` (or Trivy `fs` adapter). `--all` does not enable container. |
| Policy vs IaC | Remaining Rego gaps | Some workload kinds / stringly YAML may still diverge. |
| Redaction | Heuristic, not cryptographic | Novel secret formats may still leak in snippets. |
| CloudFormation | Not implemented | **Not planned.** Listing it under `scanners.iac.frameworks` fails validation. |
| AI scanner | Rejected at config/CLI | No scoped design yet; keep `enabled: false` until one exists. |
| OPA API | `opa/rego` v0 wrapper deprecated | Keep until Rego v1 migrate; `opa/v1` needs policy rewrite or explicit RegoV0. |

## Landed since original residual note

- Waves 1–3 on `main` (#10, #13; Wave 2 was re-landed after a non-main base merge).
- CI unit-test workflow (`.github/workflows/ci.yml`) + `make test-scripts`.
- Configurable scan deadline: `scan_timeout` / `--timeout`.
- **R0:** `v1.1.0` GitHub Release binaries + checksums; install.sh repaired; Action `timeout` input; release skips Docker when Hub secrets absent.
- **R1:** `dependencies.fail_on_error`; module-path install decision; container / baseline / SARIF CI docs.
- **R2 (quality waves):** SAST FP fixes; rules in `rules.yaml`; finding IDs with path tokens.
- **R2 (gate contract):** distinct exit codes; line-independent fingerprints; baseline v2; inline suppressions; skip warnings; git metadata via `rev-parse`/CI env; SARIF fingerprints/CWE/`security-severity`.
- **R3:** `--diff-base` / `--staged`; Action `delivery: release`; SHA-pinned workflows; GitLab/JUnit/job summary; cosign + provenance notes.
- **R4:** external adapters (`auto`/`required`/`off`); SAST v2 + Go AST; OSV batch/retry/disk cache; Go transitives; SBOM ingest.
- **R5:** artifact classifier, safe unpacker, catalogers, binary secrets, hardening, malware heuristics.
- **R6:** labeled corpus, fuzz targets, SARIF golden tests, perf-budget target.

## Optional follow-ups (not blockers)

- AI code review (keep rejected until a scoped design)
- Full Go module + GitHub repo rename (only if `go install` becomes a goal)
- Expand license DB or integrate SBOM license check (opt-in scanner remains)
- Add Docker Hub secrets and publish images on next tag
- CloudFormation only if product priority changes (currently **not planned**)
- Deeper taint/dataflow beyond Semgrep adapter + Go AST sinks

# Audit residual risks (post Waves 1–3 + R0/R1)

> **In progress on `cursor/quality-waves-abcde-c09b`:** docs/product honesty for license opt-in, lockfile-first deps, Docker Hub soft-sell, and CloudFormation “not planned.” Engine/scanner Go fixes for Waves A–E may still be in flight — treat residual rows below as open unless a later note marks them closed.

Re-audit after correctness, delivery, scanner-quality waves, first release, and R1 productize. Unit tests green; `make demo` fails the gate as expected on intentional findings.

## Residual risks

| Area | Risk | Notes |
| --- | --- | --- |
| Docker Hub | Images not published yet | `v1.1.0` (+ follow-ups) ship binaries; Hub needs `DOCKER_USERNAME` / `DOCKER_PASSWORD`. Prefer binary / Action / `make build`. |
| Module path | `go install` unsupported by decision | Module `github.com/cozygarage/sentinelflow` ≠ repo `cozyGarage/sentielflow`. Install = binary / Action / `make build` first; Docker optional. |
| License scanner | High FN rate by design | Hardcoded license map; no SBOM. **Honesty path:** opt-in only (not in `--all`). Documented; not a full license gate. |
| Dependencies | No Ruby/Gemfile parsing; range-only manifests | Lockfile-first preferred; without lockfile = best-effort. Ruby still unsupported. |
| CloudFormation | Not implemented | **Not planned** for now. Listing it under `scanners.iac.frameworks` fails validation. |
| AI scanner | Rejected at config/CLI | Planned; keep `enabled: false`. |
| OSV / network | Soft-fail optional | Default `fail_on_error: true`. Set `scanners.dependencies.fail_on_error: false` to warn instead of failing CI on transport errors. |
| Secrets git history | Requires local `git` | Errors surface; history depth via config. |
| Container delivery | Action `scan-container` needs `delivery: build` | Docker delivery path cannot run host Trivy. `--all` does not enable container. |
| Policy vs IaC | Remaining Rego gaps | e.g. some workload kinds / stringly YAML edge cases may still diverge. |
| Redaction | Heuristic, not cryptographic | Reporter + secrets redact patterns; novel secret formats may still leak in snippets. |
| SAST | Line-local regex only | Rules in `rules.yaml`; `severity`/`skip_rules` honored. No taint analysis; Go/JS/TS/Python/Java only. |

## Landed since original residual note

- Waves 1–3 on `main` (#10, #13; Wave 2 was re-landed after a non-main base merge).
- CI unit-test workflow (`.github/workflows/ci.yml`) + `make test-scripts`.
- Configurable scan deadline: `scan_timeout` / `--timeout`.
- **R0:** `v1.1.0` GitHub Release binaries + checksums; install.sh repaired; Action `timeout` input; release skips Docker when Hub secrets absent.
- **R1:** `dependencies.fail_on_error`; module-path install decision; container / baseline / SARIF CI docs.
- **R2 (partial):** SAST FP fixes (`cmd-inject-shell`, `sqli-format`, `xss-eval`); rules moved to embedded YAML; drop SAST self-scan excludes for policy/deps/container/sast sources.

## Optional follow-ups (not blockers)

- AI code review
- OSV worker pool / rate limit
- Full Go module + GitHub repo rename (only if `go install` becomes a goal)
- Expand license DB or integrate SBOM license check (opt-in scanner remains)
- Add Docker Hub secrets and publish images on next tag
- CloudFormation only if product priority changes (currently **not planned**)

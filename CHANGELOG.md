# Changelog

All notable changes to SentinelFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Load `.sentinelflow.yaml` and relative baseline paths from the scan target (not only process CWD)
- Action: `scan-*: false` opts out even when `scan-all: true`
- `count-findings.sh` counts real JSON `findings` / SARIF `results` (and text/markdown totals)
- License scanner surfaces parse/read errors instead of silently returning 0 findings

### Fixed (prior)

- IaC/policy finding IDs include a path token so baseline cannot cross-suppress sibling files
- Broken custom Rego policies always fail the policy scanner (even when builtins loaded)
- Exclude globs with multiple `**` segments (e.g. `**/testdata/**`) match correctly

### Fixed (prior)

- Selective CLI flags (`--secrets`, `--iac`, …) disable the policy scanner so OPA no longer runs unexpectedly
- Shared `filter.ShouldSkip` no longer hard-skips `*_test.go` (defaults / `scanners.exclude` / secrets allowlist handle it; `**` globs match correctly)
- Secrets finding IDs include a path token; `.sentinelflow/patterns.yaml` loads from the scan root
- Secrets git history depth honors `scanners.secrets.max_history_depth` when that feature enables history
- GitHub PAT vs App token patterns no longer double-match the same token
- IaC recognizes `*.dockerfile`; unknown `scanners.iac.frameworks` values fail validation
- Dependencies `Supports`/`Pipfile` Detect match implemented parsers (no Pipfile-alone false green)
- Text report severity headers no longer print a stray space (`(%d)`)

### Changed

- Document `scan_staged_only` as not implemented; clarify secrets `patterns` are regexes

### Fixed (SAST)

- SAST `cmd-inject-shell` alternation no longer matches bare `"bash"` / `"cmd"` strings
- SAST `sqli-format` no longer matches English `fmt.Sprintf("Update …")` remediation text
- SAST `xss-eval` matches lowercase `eval(` only (avoids Go `query.Eval`)
- Bump Go to `1.25.13` and `golang.org/x/crypto` to `v0.55.0` so `govulncheck` / deps stay green

### Changed (SAST)

- SAST rules load from embedded `rules.yaml`; removed SAST self-scan path excludes for scanner/policy/deps/container sources
- SAST honors `scanners.sast.severity` and `skip_rules`; finding IDs include a path token to avoid cross-file collisions
- SAST `Supports` limited to Go/JS/TS/Python/Java until language-specific rules exist

### Added

- SAST fixture corpus under `internal/scanner/sast/testdata/` and broader rule unit tests

## [1.1.1] - 2026-07-29

### Added

- `scanners.dependencies.fail_on_error` (default `true`) to soft-skip OSV/network errors without false greens
- R1 docs: install matrix decision (no `go install`), baseline create/update, container CI path, SARIF `always()` upload, soft-fail deps

### Changed

- Roadmap marks R0/R1 complete; residual risks updated for release + flake control

## [1.1.0] - 2026-07-29

### Added

- `scanners.exclude` global path skip list; secrets `allowlist` is secrets-only
- `scripts/count-findings.sh` and install checksum verification against `checksums.txt`
- Release runbook, post-audit residual risks, and product roadmap (R0–R3)
- License `allowed` list; redact unit tests + reporter defense-in-depth
- CI unit-test workflow + `make test-scripts`
- Configurable scan deadline (`scan_timeout` / `--timeout`)
- Visual demo README, `examples/demo-project`, `make demo`
- GitHub Action `delivery: docker` / `delivery: build`
- Restyled HTML reports; shared `test/fixtures/` corpus
- Python / Maven / Cargo dependency parsers
- Configurable scanner concurrency
- GitHub Action `timeout` input (maps to `--timeout`)
- Release workflow publishes GitHub binaries even when Docker Hub secrets are absent (`--skip=docker`)

### Changed

- Release workflow pins GoReleaser action `v6.3.0` + CLI `v2.9.0`
- Action inputs bound via `env` (no shell interpolation)
- `--all` does not enable container (Trivy opt-in via `--container`)
- Docs clarify `go install` unsupported until module path matches the GitHub repo
- Engine shares file walks; scanners use worker pools
- Default IaC frameworks: terraform, kubernetes, dockerfile only

### Fixed

- Findings preserved when scanners return `(result, err)`; container skips are visible errors
- `fail_on` / `--fail-on` case-normalized; worker/policy errors surface on `ScannerRun.Error`
- Path-scoped sample skips; K8s bool-ish YAML; policy privileged init/ephemeral alignment
- License/deps Supports honesty (no false Gemfile/Cargo claims)
- Self-scan excludes intentional scanner pattern sources
- `scripts/install.sh` parse error on extract (`find` parentheses broke `[[` parsing)

## [1.0.0] - 2026-07-12

### Added

- Multi-scanner security analysis: secrets, IaC, dependencies, SAST, container, license, and policy
- Terraform, Kubernetes, and Dockerfile misconfiguration rules
- OPA policy-as-code engine with built-in Rego policies
- OSV-backed dependency vulnerability scanning
- Report formats: text, Markdown, JSON, SARIF, and HTML
- GitHub Actions composite action and CI workflow (security scan, SBOM, policy validation)
- Pre-commit hook installer (`sentinelflow hook install`)
- Baseline filtering for incremental adoption
- MIT license

### Fixed

- Policy scanner now evaluates Rego policies at scan time (no stub)
- Dependency scanner queries OSV instead of hardcoded demo data
- `fail_on.secrets` and `fail_on.policy_violations` gates work alongside severity thresholds
- Secret and code snippets are redacted in reports
- Docker HEALTHCHECK uses `sentinelflow version`
- Git metadata collection no longer panics on trailing newlines

### Security

- Entropy-based secret detection with allowlists
- Git history secret scanning with allowlist support
- `govulncheck` in CI pipeline
- Non-root Docker container execution

[Unreleased]: https://github.com/cozyGarage/sentielflow/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/cozyGarage/sentielflow/releases/tag/v1.1.0
[1.0.0]: https://github.com/cozyGarage/sentielflow/releases/tag/v1.0.0

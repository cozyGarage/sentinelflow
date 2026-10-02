# Changelog

All notable changes to SentinelFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-10-03

Ships the R2–R6 release trains: a CI gate you can trust, diff-aware scans, deeper SAST and dependency analysis, and artifact/binary scanning.

### Upgrade notes

- **Exit codes changed.** `0` pass, `1` findings gate, `2` scanner/config error, `3` timeout. Wrappers that treat any non-zero exit as "vulnerabilities found" should handle `2`/`3` separately.
- **Baseline v2.** Fingerprints no longer include line numbers, so moving code does not reopen baselined findings. v1 baselines still load; regenerate with `sentinelflow baseline` to migrate.
- **Action path.** Use the root action (`cozyGarage/sentinelflow@v1.2.0`, or `uses: ./` in this repo). The duplicate `.github/actions/sentinelflow` copy was removed; pinned older tags keep working.
- **Go 1.27** is required to build from source.
- **Repository renamed** to `cozyGarage/sentinelflow`. Old `sentielflow` URLs redirect, but update pins. `go install github.com/cozygarage/sentinelflow/cmd/sentinelflow@v1.2.0` is now supported.

### Added

- Distinct CI exit codes (`0`/`1`/`2`/`3`) and flag validation before scanning (`--format`, `--fail-on`, `--timeout`)
- Line-independent finding fingerprints and baseline v2 (`reason`, `expires`); baseline summary counts (suppressed vs new) in CLI, JSON, and Markdown
- Inline `sentinelflow:ignore <rule-id> -- reason` suppressions; warnings for oversized/unreadable skipped files (`scanners.max_file_size`)
- `--diff-base` / `--staged`; the pre-commit hook uses `--staged`
- SARIF 2.1.0 fields GitHub code scanning uses (`partialFingerprints`, `security-severity`, CWE tags, `automationDetails`, `toolExecutionNotifications`) with a schema-checked golden test
- GitLab SAST/dependency reports, JUnit XML, `--emit-annotations`, GitHub job summary
- Action `delivery: release` (checksum-verified GitHub Release binary), version-tagged default image, and a cross-run OSV cache
- Keyless Cosign signature bundle (`checksums.txt.sigstore.json`; `VERIFY_SIGNATURE=1 install.sh`) and SLSA provenance on release checksums; release SBOMs; release binaries self-scanned with `scan-artifact`
- `scan-artifact` accepts `-o`, `--fail-on`, and `--timeout`
- Optional external adapters (Semgrep, gitleaks, Grype, Syft, Trivy `fs`, YARA) with `mode: auto|required|off`
- SAST rules.yaml v2, Go AST sinks, and Go SSA taint tracking from request input / env to shell commands
- More secret providers and opt-in `--verify-secrets`
- OSV `querybatch`, retries with backoff, 24h on-disk cache (`SENTINELFLOW_CACHE_DIR`), Go transitive deps from `go.sum`
- SBOM ingest (`scan --sbom`) and SPDX output; Cargo/poetry/Gemfile.lock versions
- License scanner reads npm lockfile license metadata
- Artifact/binary scanner: magic-byte classifier, safe unpacker, component SCA, binary secrets, ELF/PE/Mach-O hardening, malware heuristics
- Labeled precision/recall corpus, fuzz targets (unpacker, lockfiles, ELF/PE), SAST fixtures, and a small-tree perf budget test
- `sentinelflow init --force`

### Changed

- Go 1.27; Docker image builds on `golang:1.27-alpine` and runs on `alpine:3.23`
- SAST rules load from embedded `rules.yaml` and honor `scanners.sast.severity` / `skip_rules`; `path-traversal` is limited to file-open sinks; SAST `Supports` covers Go/JS/TS/Python/Java only
- Secrets are deduped per value and location; secrets `patterns` are documented as regexes
- `sentinelflow init` no longer switches default output to Markdown; it enables SAST and drops the placeholder AI block
- Builds without ldflags report version `dev` (not `1.0.0`); `make build` uses `git describe`
- GoReleaser marks `-rc` tags as prereleases; release notes lead with `install.sh` and the Action
- Dead code removed: unused API helpers, unread reporting knobs, orphan scripts and fixtures

### Removed

- Unreleased `sentinelflow db update` command and `scanners.dependencies.offline` / `cache_dir` keys: the downloaded data was never read. Use `SENTINELFLOW_CACHE_DIR` to move the cache.

### Fixed

- Release workflow: the artifact self-scan used flags `scan-artifact` did not accept, so its report upload would fail
- `docker build` failed because the builder image's Go was older than `go.mod` required
- Action `scan-all` with an individual `scan-*: false` opt-out keeps policy enabled (`--all --no-*`)
- Selective CLI flags (`--secrets`, `--iac`, …) disable the policy scanner so OPA no longer runs unexpectedly
- `.sentinelflow.yaml` and relative baseline paths load from the scan target, not only the process CWD
- Git metadata works on detached HEAD (`git rev-parse`, `GITHUB_SHA`, `CI_COMMIT_SHA`)
- IaC, policy, secrets, and SAST finding IDs include a path token so baselines cannot cross-suppress sibling files
- Broken custom Rego policies always fail the policy scanner
- Exclude globs with multiple `**` segments (e.g. `**/testdata/**`) match; `*_test.go` is no longer hard-skipped
- Concurrent scan results are ordered deterministically
- Secrets: `.sentinelflow/patterns.yaml` loads from the scan root; history depth honors `max_history_depth`; GitHub PAT vs App tokens no longer double-match
- IaC recognizes `*.dockerfile`; unknown `scanners.iac.frameworks` fail validation
- Dependencies: `Pipfile` alone no longer reports a false green
- License scanner surfaces parse/read errors instead of silently returning 0 findings
- `count-findings.sh` counts real JSON `findings` / SARIF `results`
- SAST false positives: `cmd-inject-shell` on bare `"bash"`, `sqli-format` on English `Sprintf` text, `xss-eval` on Go `query.Eval`
- Text report severity headers no longer print a stray space
- Secrets: `aws-access-key` is case-sensitive with word boundaries (matched words like `ArabianDiacritical…`); `database-url` no longer spans whitespace. Self-scan of the release binary dropped from 1 critical + 1 high false positive to none
- Artifacts: Go stdlib versions drop GOEXPERIMENT suffixes (`go1.27.0-X:…`) that made OSV report already-fixed vulns

### Security

- `golang.org/x/crypto` v0.57.0 (GO-2026-6354, GO-2026-6355)
- Workflows pin third-party actions by commit SHA; Dependabot keeps them current

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

[Unreleased]: https://github.com/cozyGarage/sentinelflow/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/cozyGarage/sentinelflow/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/cozyGarage/sentinelflow/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cozyGarage/sentinelflow/releases/tag/v1.1.0
[1.0.0]: https://github.com/cozyGarage/sentinelflow/releases/tag/v1.0.0

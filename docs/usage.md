# Usage Guide

SentinelFlow is designed to be simple yet powerful. This guide covers the most common commands and use cases.

## Install

| Method | Command |
| --- | --- |
| Source | `git clone https://github.com/cozyGarage/sentinelflow && make build` |
| Install script | `curl -fsSL https://raw.githubusercontent.com/cozyGarage/sentinelflow/main/scripts/install.sh \| bash` (verifies `checksums.txt`; pin with `VERSION=1.2.0`) |
| go install | `go install github.com/cozygarage/sentinelflow/cmd/sentinelflow@latest` (Go 1.27+; no checksum/signature step) |
| Release binary | Download from [GitHub Releases](https://github.com/cozyGarage/sentinelflow/releases) |
| Docker (optional) | `docker build -t sentinelflow/sentinelflow:local .` (prefer binary / Action / `make build`; Hub tags only when published) |

**Install decision:** prefer the install script (checksum-verified), release binary, Action, `make build`, or `go install`. Docker is optional (`docker build` locally, or Hub pull when an image is published).

Optional Docker (local image):

```bash
docker build -t sentinelflow/sentinelflow:local .
docker run --rm -v "$PWD:/workspace" -w /workspace \
  sentinelflow/sentinelflow:local scan --all .
```

## Demo

Scan the intentional sample project and emit HTML/Markdown/SARIF reports:

```bash
make demo
# → demo-out/report.html, report.md, report.sarif
```

Or:

```bash
sentinelflow scan --secrets --iac --sast examples/demo-project
```

## Basic Scan

Scan the current directory with all implemented scanners:

```bash
sentinelflow scan --all .
```

`--all` enables secrets, IaC, dependencies, and SAST. License scanning is **opt-in** (`--license` or `scanners.license.enabled`); it is **not** included in `--all`. `--all` also does **not** enable container scanning (use `--container`, requires Trivy) or AI review (`--ai` / `scanners.ai.enabled` are rejected in this release).

## Selecting Scanners

Enable specific scanners instead of running everything:

```bash
sentinelflow scan --secrets .          # Secret detection
sentinelflow scan --iac .              # Terraform, Kubernetes, Dockerfile
sentinelflow scan --deps .             # Dependency vulnerabilities (OSV)
sentinelflow scan --sast .             # OWASP-oriented static patterns
sentinelflow scan --license .          # License policy checks (opt-in; not in --all)
sentinelflow scan --container .        # Container image scan (requires Trivy)
sentinelflow scan --container --container-image myapp:latest
sentinelflow scan --artifacts .        # Binaries and archives (opt-in; not in --all)
sentinelflow scan --diff-base origin/main
sentinelflow scan --baseline-ref origin/main --fail-on high   # fail only on findings new since main
sentinelflow scan --staged --secrets --iac --fail-on high
sentinelflow scan --sbom sbom.cdx.json
sentinelflow scan-artifact dist/app --fail-on critical -f json -o artifact-scan.json

```

Combine flags as needed:

```bash
sentinelflow scan --secrets --iac --deps --fail-on high
```

Opt out of one scanner while keeping `--all` (and the default policy scanner):

```bash
sentinelflow scan --all --no-secrets .
```

`--no-secrets`, `--no-iac`, `--no-deps`, and `--no-sast` apply only with `--all`. Passing `--secrets` alone still disables policy.

## Output Formats

| Format | Description | Use case |
| --- | --- | --- |
| `text` (default) | Human-readable console output | Local development |
| `json` | Machine-readable findings | Automation, dashboards |
| `sarif` | SARIF 2.1.0 (fingerprints, CWE, security-severity) | GitHub code scanning |
| `markdown` | Styled report | PR comments, job summary |
| `html` | Browser-friendly report | Sharing with stakeholders |
| `junit` | JUnit XML | Generic CI test reports |
| `gitlab-sast` | GitLab `gl-sast-report.json` | GitLab SAST widget |
| `gitlab-deps` | GitLab `gl-dependency-scanning-report.json` | GitLab dependency scanning |

```bash
sentinelflow scan --all -f sarif -o report.sarif
sentinelflow scan --all -f markdown -o report.md
sentinelflow scan --all -f junit -o report.xml
sentinelflow scan --all -f gitlab-sast -o gl-sast-report.json
```

`--emit-annotations` prints GitHub workflow commands (`::error file=…`). In GitHub Actions the CLI also appends a Markdown summary to `$GITHUB_STEP_SUMMARY` when that file is set.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Pass — no gate tripped |
| `1` | Findings exceeded `--fail-on` / `fail_on` gates |
| `2` | Scanner or configuration error |
| `3` | Scan timed out |

Do not treat every non-zero exit as “vulnerabilities found”; `2` and `3` mean the tool did not finish cleanly.

## Failure Thresholds

Control when the process exits with code `1` (for CI gates):

```bash
# Fail on critical or high severity findings
sentinelflow scan --all --fail-on high
sentinelflow scan --all --timeout 15m

# Fail only on critical
sentinelflow scan --all --fail-on critical
```

CLI `--timeout` overrides `scan_timeout` in `.sentinelflow.yaml` (default `10m`).
Accepted `--fail-on` values: `critical`, `high`, `medium`, `low`. Each level includes all severities above it.

Additional gates are configured in `.sentinelflow.yaml`:

```yaml
fail_on:
  severity: high
  secrets: true              # Fail on any secret finding
  policy_violations: true    # Fail on any OPA policy violation
```

All configured gates are evaluated independently — a single secret or policy violation fails the scan even if severity is below the threshold.

## Policy Commands

```bash
sentinelflow policy list                    # List built-in policies
sentinelflow policy validate policies/*.rego
sentinelflow policy test policies/my.rego test/fixtures/policy/k8s-privileged-pod.json
sentinelflow policy generate my-custom-rule
```

## Supply Chain

Generate a CycloneDX or SPDX SBOM, or scan an existing SBOM:

```bash
sentinelflow sbom -o sbom.json
sentinelflow sbom --sbom-format spdx -o sbom.spdx.json
sentinelflow scan --sbom sbom.json --fail-on high
```

Inline suppressions (same line or the line above):

```
os.Open(p) // sentinelflow:ignore path-traversal -- test fixture
```

Directives are read only from comments, and file access stays within the scan root. `strict_ignores: true` requires a specific rule and non-empty `-- reason`; legacy mode continues to accept wildcard and reasonless directives. JSON reports retain redacted suppression observations so teams can audit which policy source filtered a finding.

`--verify-secrets` is opt-in live verification against provider APIs (network). Off by default.

## Git Hooks

Install a pre-commit hook for local shift-left scanning:

```bash
sentinelflow hook install
sentinelflow hook uninstall
```

## Baselines

Create or refresh a baseline from the current scan result, then filter on later scans:

```bash
# Write .sentinelflow/baseline.yaml from today's findings
sentinelflow baseline . -o .sentinelflow/baseline.yaml

# Or regenerate after accepting new debt
sentinelflow baseline . --output .sentinelflow/baseline.yaml

# Apply filtering (CLI flag or config)
sentinelflow scan --all --baseline
```

Configure in `.sentinelflow.yaml`:

```yaml
baseline:
  enabled: true
  file: .sentinelflow/baseline.yaml
```

When suppressions apply, JSON includes redacted `suppressed` observations (fingerprint, source, generic reason and authority); the `baseline` summary reconciles `total = suppressed + new` and includes source subtotals. The fail gate uses only the final `new` findings. Suppressed records omit paths, snippets and raw finding values. Repository provenance means self-attested input, not independent approval.

Baseline v2 matches line-independent fingerprints (`rule + path + value/snippet hash`) and supports `reason` and `expires`. An `expires: YYYY-MM-DD` entry is valid through that date in UTC and expires at the next midnight UTC; malformed expiry dates do not suppress findings. v1 files still load.

In GitHub Actions, set `use-baseline: 'true'` (requires the baseline file committed). See [cicd-integration.md](cicd-integration.md).

## Offline Scanning

For air-gapped or rate-limited CI, download OSV's advisories once and scan without network access:

```bash
sentinelflow db update                         # all ecosystems (~18 MB on disk, under a minute)
sentinelflow db update --ecosystems go,pip     # or just the ones you use
sentinelflow db status                         # source, acquisition time and snapshot digest
sentinelflow scan --deps --offline             # or scanners.dependencies.offline: true
sentinelflow scan --deps --require-fresh-offline-db --offline-max-age 720h
```

The database lives in `$SENTINELFLOW_CACHE_DIR/offline` (default `~/.cache/sentinelflow/vulndb/offline`). Each index records its OSV export source, SHA-256 snapshot ID, ecosystem, schema and acquisition timestamp; `db status` reads these fields from the index, so touching a file cannot make old data look fresh. Scan JSON records the queried live/offline/cache mode and any known snapshot identity. In CI, restore that directory from a cache and refresh it on a schedule. Offline mode also applies to `scan --sbom` and `scan --artifacts`, and it skips EPSS/KEV enrichment. Version ranges are evaluated locally: real semver for `SEMVER` ranges, and segment-wise numeric ordering for ecosystem ranges (Maven/PyPI/RubyGems/NuGet/Packagist). Exotic qualifiers such as `1.0.post1` or `-sp1` may order differently from the online API.

Freshness enforcement is opt-in to preserve existing air-gapped workflows. Set `scanners.dependencies.offline_require_fresh: true` and optionally `offline_max_age: 720h`, or use the CLI flags above. Strict mode implies offline lookup and makes missing, corrupt, unknown-age or older-than-limit snapshots a hard scanner error, including when `fail_on_error: false`; diagnostics include the affected ecosystem and refresh command. The age comes from snapshot metadata, never the cache file's modification time. Schedule `sentinelflow db update` before scans so the required evidence remains available.

## Git History Secret Scanning

Enable in configuration (requires `fetch-depth: 0` in CI checkout):

```yaml
git:
  scan_history: true
  history_depth: 50
```

## Verbose Mode

```bash
sentinelflow scan --all --verbose
```

Shows target path, enabled scanners, and per-scanner timing in the summary.

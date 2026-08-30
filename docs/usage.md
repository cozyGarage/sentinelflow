# Usage Guide

SentinelFlow is designed to be simple yet powerful. This guide covers the most common commands and use cases for v1.0.

## Install

| Method | Command |
| --- | --- |
| Source | `git clone https://github.com/cozyGarage/sentielflow && make build` |
| Install script | `curl -fsSL https://raw.githubusercontent.com/cozyGarage/sentielflow/main/scripts/install.sh \| bash` (verifies `checksums.txt`; pin with `VERSION=1.1.1`) |
| Release binary | Download from [GitHub Releases](https://github.com/cozyGarage/sentielflow/releases) |
| Docker (optional) | `docker build -t sentinelflow/sentinelflow:local .` (prefer binary / Action / `make build`; Hub tags only when published) |

**Install decision:** prefer the install script, release binary, Action, or `make build`. Docker is optional (`docker build` locally, or Hub pull when an image is published). `go install` is **not supported** (module path `github.com/cozygarage/sentinelflow` ≠ GitHub repo `cozyGarage/sentielflow`). Rename is deferred; do not advertise `go install`.

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
```

Combine flags as needed:

```bash
sentinelflow scan --secrets --iac --deps --fail-on high
```

## Output Formats

| Format | Description | Use case |
| --- | --- | --- |
| `text` (default) | Human-readable console output | Local development |
| `json` | Machine-readable findings | Automation, dashboards |
| `sarif` | Static Analysis Results Format | GitHub/GitLab Security tab |
| `markdown` | Styled report | PR comments, wikis |
| `html` | Browser-friendly report | Sharing with stakeholders |

```bash
sentinelflow scan --all -f sarif -o report.sarif
sentinelflow scan --all -f markdown -o report.md
```

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

Generate a CycloneDX SBOM:

```bash
sentinelflow sbom -o sbom.json
```

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

In GitHub Actions, set `use-baseline: 'true'` (requires the baseline file committed). See [cicd-integration.md](cicd-integration.md).

## Git History Secret Scanning

Enable in configuration (requires `fetch-depth: 0` in CI checkout):

```yaml
scanners:
  secrets:
    scan_git_history: true
    max_history_depth: 50

git:
  scan_history: true
  history_depth: 50
```

## Verbose Mode

```bash
sentinelflow scan --all --verbose
```

Shows target path, enabled scanners, and per-scanner timing in the summary.

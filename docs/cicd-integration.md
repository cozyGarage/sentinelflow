# CI/CD Integration

SentinelFlow integrates with GitHub Actions, GitLab CI, and Docker-based pipelines.

## GitHub Actions

### Using the composite action (recommended)

The repo root `action.yml` is the composite action (`uses: ./` in this repo, `cozyGarage/sentinelflow@<tag>` elsewhere):

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0

      - uses: ./
        with:
          delivery: build
          scan-all: 'true'
          fail-on: high
          format: sarif
          output: report.sarif

      - uses: github/codeql-action/upload-sarif@60168efe1c415ce0f5521ea06d5c2062adbeed1b # v3.28.17
        if: always()
        with:
          sarif_file: report.sarif
          category: sentinelflow
```

External repos without Docker Hub — **`delivery: release`** downloads the GitHub Release binary and verifies `checksums.txt`:

```yaml
      - uses: cozyGarage/sentinelflow@v1.2.0
        with:
          delivery: release
          scan-all: 'true'
          fail-on: high
          format: sarif
          output: report.sarif
```

External repos when a Hub image is published:

```yaml
      - uses: cozyGarage/sentinelflow@v1.2.0
        with:
          delivery: docker
          image: sentinelflow/sentinelflow:v1.2.0
          scan-all: 'true'
          fail-on: high
          format: sarif
          output: report.sarif
```

`delivery: build` is preferred for this repo. `delivery: release` is the default for external repos (no Hub required). `delivery: docker` pulls `image` once a release image is published. `delivery: build` only works when the SentinelFlow source tree is in the workspace.

Third-party `uses:` in this repository are pinned by commit SHA (Dependabot keeps them current). When you copy snippets, prefer SHA pins over floating tags.

### Action inputs

| Input | Default | Description |
| --- | --- | --- |
| `delivery` | `release` | `release` downloads a GitHub Release binary and verifies `checksums.txt`; `docker` pulls `image`; `build` compiles from the workspace (same-repo only) |
| `image` | `sentinelflow/sentinelflow:v1.2.0` | Container image when `delivery=docker` |
| `version` | action ref / latest | Release tag for `delivery=release` |
| `scan-all` | `true` | Enable secrets, IaC, deps, SAST (does **not** enable container, license, or artifacts). Individual `scan-*: 'false'` inputs **opt out** even when `scan-all` is true. Policy stays at the config default (enabled) on that path. `scan-all: 'false'` plus selective scanners still disables policy, matching `--secrets` without `--all` |
| `scan-secrets` | `true` | Secret scanning |
| `scan-iac` | `true` | IaC scanning |
| `scan-deps` | `true` | Dependency scanning |
| `scan-sast` | `true` | OWASP SAST rules |
| `scan-license` | `false` | License policy checks (**opt-in**; not part of `scan-all` / `--all`) |
| `scan-artifacts` | `false` | Binary/archive scanning (**opt-in**; not part of `scan-all`) |
| `scan-container` | `false` | Container scan (requires `delivery=build` or `release` + Trivy) |
| `container-image` | — | Image to scan when container enabled |
| `use-baseline` | `false` | Skip baselined findings. CLI, JSON, and Markdown reports include suppressed vs new counts; the fail gate uses the new (post-filter) set |
| `fail-on` | `high` | Pipeline failure threshold |
| `timeout` | — | Scan deadline (`10m`, `90s`, …); empty uses config default |
| `diff-base` | — | Limit findings to files/lines changed since this git ref |
| `emit-annotations` | `false` | Print GitHub workflow annotations |
| `format` | `sarif` | Report format (`text`, `json`, `sarif`, `markdown`, `html`, `junit`, `gitlab-sast`, `gitlab-deps`) |
| `output` | `report.sarif` | Output file path |

### Container scanning in CI

`scan-container` needs Trivy on the runner. Use `delivery: build` or `delivery: release` (host binary). The Docker delivery image does not include Trivy.

```yaml
      - uses: ./
        with:
          delivery: build
          scan-all: 'false'
          scan-secrets: 'true'
          scan-container: 'true'
          container-image: myapp:${{ github.sha }}
          fail-on: high
          format: sarif
          output: report.sarif
```

### Baseline in CI

Generate locally, commit `.sentinelflow/baseline.yaml`, then enable filtering:

```bash
sentinelflow baseline . -o .sentinelflow/baseline.yaml
```

```yaml
      - uses: cozyGarage/sentinelflow@main
        with:
          delivery: docker
          image: sentinelflow/sentinelflow:<tag>
          use-baseline: 'true'
          fail-on: high
          format: sarif
          output: report.sarif
```

Use `delivery: build` instead when no Hub image is available.

### SARIF upload (code scanning)

Upload even when the security gate fails so findings still land in the GitHub Security tab:

```yaml
      - uses: github/codeql-action/upload-sarif@60168efe1c415ce0f5521ea06d5c2062adbeed1b # v3.28.17
        if: always()
        with:
          sarif_file: report.sarif
          category: sentinelflow
```

Requires `permissions: security-events: write` on the job.

### Soft-fail OSV / dependency network errors

Default is strict (`fail_on_error: true`). For flaky CI networks only:

```yaml
scanners:
  dependencies:
    fail_on_error: false
```

Findings collected before the error still apply `fail_on`; only the transport/scanner error becomes a warning.

### SBOM and policy validation

This repository's workflow runs three jobs:

1. **security-scan** — Full scan, SARIF upload, PR comments
2. **supply-chain** — SBOM generation (`sentinelflow sbom`)
3. **policy-check** — Validates all `.rego` policies

See [.github/workflows/security-scan.yml](../.github/workflows/security-scan.yml) for the full pipeline.

### PR comments

The workflow generates a Markdown report and updates an existing bot comment when possible. The report step uses `continue-on-error: true` so PR feedback is posted even when the security gate fails.

## GitLab CI

Prefer build-from-source (or a release binary). Use a published image only when Hub tags exist:

```yaml
stages:
  - security

sentinelflow:
  stage: security
  image: golang:1.27
  script:
    - go build -o sentinelflow ./cmd/sentinelflow
    - ./sentinelflow scan --all --format gitlab-sast -o gl-sast-report.json --fail-on high
    - ./sentinelflow scan --deps --format gitlab-deps -o gl-dependency-scanning-report.json || true
    - ./sentinelflow sbom -o sbom.json
  artifacts:
    reports:
      sast: gl-sast-report.json
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - sbom.json
```

Optional container path (when an image is published):

```yaml
sentinelflow:
  stage: security
  image: sentinelflow/sentinelflow:<tag>
  script:
    - sentinelflow scan --all --format sarif -o gl-sast-report.sarif --fail-on high
```

See [examples/.gitlab-ci.yml](../examples/.gitlab-ci.yml) for a complete source-based example with policy validation.

## Docker (optional)

```bash
docker build -t sentinelflow/sentinelflow:local .
docker run --rm -v $(pwd):/workspace -w /workspace sentinelflow/sentinelflow:local scan --all
```

Prefer `make build` / install script when you do not need a container.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Pass |
| `1` | Findings exceeded `--fail-on` |
| `2` | Scanner or configuration error |
| `3` | Timeout |

Gate on `1` for “risk found”. Treat `2`/`3` as infrastructure failures, not a clean bill of health.

## Recommended settings

| Setting | CI recommendation |
| --- | --- |
| `--fail-on` | `high` or `critical` |
| `--format` | `sarif` for GitHub/GitLab security tabs |
| `--all` | Enable secrets, IaC, deps, SAST (not container, not license) |
| `fetch-depth: 0` | Required for git history secret scanning |
| Config file | Commit `.sentinelflow.yaml` to the repo |

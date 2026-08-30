# CI/CD Integration

SentinelFlow integrates with GitHub Actions, GitLab CI, and Docker-based pipelines.

## GitHub Actions

### Using the composite action (recommended)

The repo includes a composite action at `.github/actions/sentinelflow` (also published as root `action.yml`):

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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: cozyGarage/sentielflow/.github/actions/sentinelflow@main
        with:
          delivery: docker
          image: sentinelflow/sentinelflow:latest
          scan-all: 'true'
          fail-on: high
          format: sarif
          output: report.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: report.sarif
          category: sentinelflow
```

For the same repository (dogfood PR code), build from source:

```yaml
      - uses: ./.github/actions/sentinelflow
        with:
          delivery: build
          scan-all: 'true'
          fail-on: high
          format: sarif
          output: report.sarif
```

`delivery: docker` (default) pulls `image` and is the right path for **external** repos once a release image is published. `delivery: build` only works when the SentinelFlow source tree is in the workspace.

### Action inputs

| Input | Default | Description |
| --- | --- | --- |
| `delivery` | `docker` | `docker` pulls `image`; `build` compiles from the workspace (same-repo only) |
| `image` | `sentinelflow/sentinelflow:latest` | Container image when `delivery=docker` |
| `scan-all` | `true` | Enable secrets, IaC, deps, SAST, license (does **not** enable container). Individual `scan-*: 'false'` inputs **opt out** even when `scan-all` is true |
| `scan-secrets` | `true` | Secret scanning |
| `scan-iac` | `true` | IaC scanning |
| `scan-deps` | `true` | Dependency scanning |
| `scan-sast` | `true` | OWASP SAST rules |
| `scan-license` | `true` | License policy checks |
| `scan-container` | `false` | Container scan (requires `delivery=build` + Trivy) |
| `container-image` | — | Image to scan when container enabled |
| `use-baseline` | `false` | Skip baselined findings |
| `fail-on` | `high` | Pipeline failure threshold |
| `timeout` | — | Scan deadline (`10m`, `90s`, …); empty uses config default |
| `format` | `sarif` | Report format (`text`, `json`, `sarif`, `markdown`, `html`) |
| `output` | `report.sarif` | Output file path |

### Container scanning in CI

`scan-container` needs Trivy on the runner. Use `delivery: build` (this repo or a checkout that can `go build`). The Docker delivery image does not include Trivy.

```yaml
      - uses: ./.github/actions/sentinelflow
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
      - uses: cozyGarage/sentielflow/.github/actions/sentinelflow@main
        with:
          delivery: docker
          image: sentinelflow/sentinelflow:latest
          use-baseline: 'true'
          fail-on: high
          format: sarif
          output: report.sarif
```

### SARIF upload (code scanning)

Upload even when the security gate fails so findings still land in the GitHub Security tab:

```yaml
      - uses: github/codeql-action/upload-sarif@v3
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

Prefer the published image (after a release):

```yaml
stages:
  - security

sentinelflow:
  stage: security
  image: sentinelflow/sentinelflow:latest
  script:
    - sentinelflow scan --all --format sarif -o gl-sast-report.sarif --fail-on high
    - sentinelflow sbom -o sbom.json
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    paths:
      - sbom.json
```

Build from source when dogfooding this repository:

```yaml
sentinelflow:
  stage: security
  image: golang:1.25
  script:
    - go build -o sentinelflow ./cmd/sentinelflow
    - ./sentinelflow scan --all --format sarif -o gl-sast-report.sarif --fail-on high
```

See [examples/.gitlab-ci.yml](../examples/.gitlab-ci.yml) for a complete source-based example with policy validation.

## Docker

```bash
docker build -t sentinelflow .
docker run --rm -v $(pwd):/workspace -w /workspace sentinelflow scan --all
```

## Exit codes

SentinelFlow exits with code `1` when findings exceed the `--fail-on` threshold. Use this to gate merges.

## Recommended settings

| Setting | CI recommendation |
| --- | --- |
| `--fail-on` | `high` or `critical` |
| `--format` | `sarif` for GitHub/GitLab security tabs |
| `--all` | Enable all implemented scanners |
| `fetch-depth: 0` | Required for git history secret scanning |
| Config file | Commit `.sentinelflow.yaml` to the repo |

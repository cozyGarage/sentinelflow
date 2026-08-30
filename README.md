# SentinelFlow

<p align="center">
  <img src="docs/assets/logo.png" alt="SentinelFlow logo" width="200" />
</p>

<p align="center">
  <strong>CI/CD Security Gatekeeper</strong><br/>
  Secrets · IaC · Dependencies · SAST · Policy · SBOM — one binary for the pipeline.
</p>

<p align="center">
  <a href="https://github.com/cozyGarage/sentielflow/actions/workflows/security-scan.yml"><img src="https://github.com/cozyGarage/sentielflow/actions/workflows/security-scan.yml/badge.svg" alt="Security Scan" /></a>
  <a href="https://github.com/cozyGarage/sentielflow/releases"><img src="https://img.shields.io/github/v/release/cozyGarage/sentielflow?label=release" alt="Release" /></a>
  <a href="https://hub.docker.com/r/sentinelflow/sentinelflow"><img src="https://img.shields.io/badge/docker-sentinelflow%2Fsentinelflow-0db7ed" alt="Docker" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License" /></a>
</p>

<p align="center">
  <img src="docs/assets/banner.jpg" alt="SentinelFlow banner" width="100%" />
</p>

SentinelFlow scans your repo for leaked secrets, insecure infrastructure, vulnerable dependencies, and policy violations — then fails the build when gates trip.

## See it in action

<p align="center">
  <img src="docs/assets/screenshots/cli-scan.png" alt="CLI scan of examples/demo-project" width="100%" />
</p>

<p align="center">
  <img src="docs/assets/screenshots/report-html.png" alt="Real HTML report from the demo project" width="100%" />
</p>

| Pipeline gate | Shift-left workflow |
| :---: | :---: |
| <img src="docs/assets/screenshots/cicd-flow.png" alt="CI/CD pipeline with SentinelFlow gate" width="100%" /> | <img src="docs/assets/hacker.jpg" alt="Shift-left security illustration" width="100%" /> |

### 60-second demo

```bash
# From a clone (preferred)
make build && make demo

# Or install a release binary, then:
# sentinelflow scan --secrets --iac --sast examples/demo-project

# Optional: local Docker image (Hub :latest is not always published)
docker build -t sentinelflow/sentinelflow:local .
docker run --rm -v "$PWD:/workspace" -w /workspace \
  sentinelflow/sentinelflow:local \
  scan --secrets --iac --sast examples/demo-project
```

`make demo` scans [`examples/demo-project`](examples/demo-project) (intentional findings) and writes `demo-out/report.{html,md,sarif}`.

Checked-in samples: [`docs/assets/demo/`](docs/assets/demo/).

## Install

| Method | Best for | How |
| --- | --- | --- |
| **Install script** | Laptops | `curl -fsSL …/scripts/install.sh \| bash` (verifies checksums) |
| **Clone + build** | Contributors | `git clone … && make build` |
| **GitHub Action** | Pull requests | `delivery: build` (this repo) or `delivery: docker` when a Hub image is published |
| **Docker** (optional) | CI when an image exists | `docker build -t sentinelflow/sentinelflow:local .` — Hub tags only when Docker credentials are configured on release |

> **v1.1.1** ships GitHub Release binaries + `checksums.txt`. Prefer binary / Action / `make build`. Docker Hub images publish only when `DOCKER_USERNAME` / `DOCKER_PASSWORD` are set (see [docs/releasing.md](docs/releasing.md)); do not assume `:latest` is on Hub.
>
> **Install matrix:** binary / Action / `make build` first; Docker optional. `go install` is **not supported** (module path ≠ GitHub repo name).

### Build from source

```bash
git clone https://github.com/cozyGarage/sentielflow
cd sentielflow
make build
./sentinelflow version
```

### Docker (optional)

```bash
# Local image from this repo
docker build -t sentinelflow/sentinelflow:local .
docker run --rm -v "$PWD:/workspace" -w /workspace \
  sentinelflow/sentinelflow:local \
  scan --all --format sarif -o report.sarif

# Only if a Hub image was published for this tag:
# docker pull sentinelflow/sentinelflow:<tag>
```

Compose helpers: [`docker-compose.yml`](docker-compose.yml) (`scan-html`, `scan-sarif`, `scan-markdown`) — expect a local or published image.

### Release binary

```bash
curl -fsSL https://raw.githubusercontent.com/cozyGarage/sentielflow/main/scripts/install.sh | bash
# or pin: VERSION=1.1.1 ./scripts/install.sh
./bin/sentinelflow version
```

### GitHub Action

Same repository (preferred while Hub images are optional):

```yaml
- uses: ./.github/actions/sentinelflow
  with:
    delivery: build
    fail-on: high
    format: sarif
    output: report.sarif
```

External repos when a published image is available:

```yaml
- uses: cozyGarage/sentielflow/.github/actions/sentinelflow@main
  with:
    delivery: docker
    image: sentinelflow/sentinelflow:<tag>
    fail-on: high
    format: sarif
    output: report.sarif
```

## Features

- **Secret scanning** — tokens, passwords, entropy, optional git history
- **Infrastructure-as-Code** — Terraform, Kubernetes, Dockerfiles
- **Dependencies** — OSV lookup (Go/npm/PyPI/Maven/Cargo)
- **SAST** — OWASP-oriented static patterns
- **Container** — Trivy when available
- **License policy** — opt-in (`--license`); deny GPL/AGPL/SSPL-style licenses (limited map)
- **Policy-as-code** — embedded OPA/Rego built-ins
- **SBOM** — CycloneDX
- **Reports** — text, Markdown, SARIF, JSON, HTML

> AI-powered review is **planned**. `--ai` / `scanners.ai.enabled` are rejected in this release.

## Configuration

```yaml
version: "1.0"
scanners:
  secrets: { enabled: true }
  iac:
    enabled: true
    frameworks: [terraform, kubernetes, dockerfile]
  dependencies: { enabled: true, ecosystems: [auto] }
fail_on:
  severity: high
  secrets: true
  policy_violations: true
```

Full reference: [docs/configuration.md](docs/configuration.md).

## CI/CD

```yaml
name: Security Scan
on: [pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ./.github/actions/sentinelflow
        with:
          delivery: build
          fail-on: high
          format: sarif
          output: report.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: report.sarif
```

GitLab (build from source; or use a published image when available):

```yaml
sentinelflow:
  image: golang:1.25
  script:
    - go build -o sentinelflow ./cmd/sentinelflow
    - ./sentinelflow scan --all --format sarif -o gl-security-report.sarif
  artifacts:
    reports:
      sast: gl-security-report.sarif
```

More: [docs/cicd-integration.md](docs/cicd-integration.md).

## Documentation

- [Usage](docs/usage.md) · [Configuration](docs/configuration.md) · [Scanners](docs/scanners.md)
- [Policies](docs/policies.md) · [CI/CD](docs/cicd-integration.md) · [Architecture](docs/architecture.md)

## Development

```bash
go test ./...
make build
make demo
make scan-self
```

## Security

- Findings are redacted; secrets are not stored or exfiltrated
- Scanning is local by default (OSV receives package names/versions only)
- Container image runs as a non-root user

## License

MIT — see [LICENSE](LICENSE).

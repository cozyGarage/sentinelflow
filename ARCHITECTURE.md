# SentinelFlow Architecture

SentinelFlow is a Go-based security scanner for CI/CD pipelines. For detailed diagrams and pipeline flow, see [docs/architecture.md](docs/architecture.md).

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SentinelFlow v1.0                         │
├─────────────────────────────────────────────────────────────────┤
│  CLI (Cobra)  →  Config (Viper)  →  Scanner Engine               │
│                          ↓                                       │
│    ┌─────────┬─────────┬─────────┬─────────┬─────────┬────────┐ │
│    │ Secrets │   IaC   │  Deps   │  SAST   │Container│ License │ │
│    └────┬────┴────┬────┴────┬────┴────┬────┴────┬────┴───┬────┘ │
│         └─────────┴─────────┴─────────┴─────────┴──────────┘      │
│                          ↓                                       │
│                   Policy Engine (OPA)                            │
│                          ↓                                       │
│              Reporter (SARIF, JSON, Markdown, HTML)               │
└─────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology |
| --- | --- |
| CLI | Cobra + Viper |
| Secret Scanner | Regex, Shannon entropy, git history |
| IaC Scanner | Terraform, Kubernetes YAML, Dockerfile rules |
| Dependency Scanner | Lockfile parsing + OSV API |
| SAST | OWASP-oriented regex rules |
| Container | Trivy integration |
| License | Manifest parsing + deny list |
| Policy Engine | Open Policy Agent (Rego) |
| SBOM | CycloneDX generation |
| Reports | Text, JSON, SARIF, Markdown, HTML |

## Directory Structure

```
sentinelflow/
├── cmd/sentinelflow/       # CLI entry point
├── internal/
│   ├── adapter/            # Scanner adapters for the engine
│   ├── cli/                # Cobra commands
│   ├── config/             # Configuration management
│   ├── reporter/           # Report formatters
│   ├── scanner/            # Scanner implementations
│   │   ├── secrets/
│   │   ├── iac/
│   │   ├── dependencies/
│   │   ├── sast/
│   │   ├── container/
│   │   ├── license/
│   │   ├── policy/
│   │   ├── sbom/
│   │   └── redact/
│   └── vulndb/             # OSV vulnerability database client
├── pkg/api/                # Public types
├── policies/               # Built-in Rego policies
├── docs/                   # Documentation
├── test/                   # Integration tests
├── Dockerfile
├── Makefile
└── go.mod
```

## Scanner Engine

The engine (`internal/scanner/engine.go`) orchestrates enabled scanners concurrently:

1. Collect files from the target path (skipping `.git`, `node_modules`, etc.)
2. Run each enabled scanner in parallel
3. Apply baseline filtering when configured
4. Aggregate findings into a single `ScanResult`
5. Pass results to the reporter

Scanners are registered based on configuration:

| Config flag | Scanner |
| --- | --- |
| `scanners.secrets.enabled` | Secrets |
| `scanners.iac.enabled` | IaC |
| `scanners.dependencies.enabled` | Dependencies |
| `scanners.sast.enabled` | SAST |
| `scanners.container.enabled` | Container |
| `scanners.license.enabled` | License |
| `policies.enabled` | Policy (OPA) |

## Planned Features

- **AI code review** — LLM-powered analysis (`scanners.ai` / `--ai`); enabling is rejected until the scanner ships.
- **CloudFormation scanning** — Not planned / unsupported; listing it under `scanners.iac.frameworks` fails validation. Defaults are terraform, kubernetes, and dockerfile.

## CI/CD Integration

SentinelFlow runs as a standalone binary in CI pipelines. The repository workflow includes:

- **Security Scan** — `govulncheck`, full scan, SARIF upload
- **Supply Chain** — SBOM artifact
- **Policy Validation** — Rego syntax checks

See [docs/cicd-integration.md](docs/cicd-integration.md) for GitHub Actions and GitLab CI examples.

## Security Principles

1. **No secret storage** — Findings are redacted; secrets are never persisted
2. **Local first** — Scanning runs locally; only package names/versions are sent to OSV
3. **Static analysis** — Code is analyzed without execution
4. **Non-root container** — Docker image runs as unprivileged user

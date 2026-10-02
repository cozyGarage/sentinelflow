# SentinelFlow Documentation

Welcome to the SentinelFlow v1.0 documentation.

## Documentation Index

| Document | Description |
| --- | --- |
| [Usage Guide](usage.md) | CLI commands, flags, and common workflows |
| [Configuration Reference](configuration.md) | `.sentinelflow.yaml` options |
| [Scanner Details](scanners.md) | How each scanner works |
| [Policy Authoring](policies.md) | Writing and testing OPA/Rego policies |
| [CI/CD Integration](cicd-integration.md) | GitHub Actions, GitLab CI, Docker |
| [Releasing](releasing.md) | `v*` tags, Docker Hub secrets, install checksums |
| [Roadmap](roadmap.md) | Robustness trains R2–R6 (gate, CI, code depth, artifacts, quality) |
| [Audit residual risks](audit-residual-risks.md) | Known gaps after the audit improvement cycle |
| [Architecture](architecture.md) | Engine design and scan pipeline |

## Quick Links

- [GitHub Repository](https://github.com/cozyGarage/sentielflow)
- [Live demo project](../examples/demo-project) — `make demo`
- [Sample HTML report](assets/demo/report.html)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [Changelog](../CHANGELOG.md)
- [Architecture Overview](../ARCHITECTURE.md)

## Requirements

- Go 1.27+ (version pinned in `go.mod`), **or** Docker / a GitHub Release binary
- Optional: [Trivy](https://github.com/aquasecurity/trivy) for container scanning

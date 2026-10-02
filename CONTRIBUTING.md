# Contributing to SentinelFlow

Thank you for your interest in contributing to SentinelFlow! We welcome contributions from the community to make this tool better for everyone.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/YOUR_USERNAME/sentinelflow.git
    cd sentinelflow
    ```
3.  **Create a branch** for your feature or bug fix:
    ```bash
    git checkout -b feature/amazing-feature
    ```

## Development Environment

SentinelFlow is built with Go **1.27+** (see the `go` directive in `go.mod`).

### Prerequisites

- Go 1.27 or higher (matches `go.mod`)
- Docker (optional, for testing container builds)
- Make (optional, for running helper scripts)

### Installation

1.  Install dependencies:
    ```bash
    go mod download
    ```
2.  Build the binary:
    ```bash
    go build -o sentinelflow ./cmd/sentinelflow
    ```

## Testing

We prioritize high-quality code. Please ensure all tests pass before submitting a PR.

### Running Unit Tests

```bash
go test ./... -v
```

### Running Integration Tests

Integration tests require building the binary first.

```bash
go test -tags=integration ./test -v
```

### Running Benchmarks

If you are modifying performance-critical code, please run benchmarks:

```bash
go test -bench=. ./internal/...
```

## Project Structure

- `cmd/sentinelflow`: Main entry point and CLI commands.
- `internal/scanner`: Core scanner logic (Secrets, IaC, Dependencies, Engine).
- `internal/reporter`: Reporting logic (SARIF, JSON, Markdown, etc.).
- `internal/config`: Configuration handling.
- `policies`: Built-in OPA policies.

## Coding Standards

- Follow standard Go idioms and formatting (`gofmt`).
- Ensure all new code has unit tests.
- Document exported functions and types.
- Keep the `README.md` and `CHANGELOG.md` updated if necessary.

## Submitting a Pull Request

1.  **Commit your changes** with descriptive commit messages.
    - We follow [Conventional Commits](https://www.conventionalcommits.org/): `feat: add new scanner`, `fix: resolve crash in parser`.
2.  **Push to your fork**:
    ```bash
    git push origin feature/amazing-feature
    ```
3.  **Open a Pull Request** on the main repository.
4.  Describe your changes clearly and link to any relevant issues.

## Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub. include:

- Steps to reproduce
- Expected behavior
- Actual behavior
- SentinelFlow version (`sentinelflow version`)
- OS and architecture

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

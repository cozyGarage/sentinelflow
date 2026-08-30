# Releasing SentinelFlow

GoReleaser publishes GitHub Release assets (`checksums.txt` + platform archives) on `v*` tags. Docker Hub images are published **only when** `DOCKER_USERNAME` / `DOCKER_PASSWORD` are set; otherwise the workflow uses `--skip=docker` so binaries still ship. Prefer install script / GitHub Release binaries over assuming a Hub `:latest` pull.

## Prerequisites

| Secret | Required? | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | Automatic | Create GitHub Release + upload assets |
| `DOCKER_USERNAME` | Optional | Docker Hub username for `sentinelflow/sentinelflow` |
| `DOCKER_PASSWORD` | Optional | Docker Hub access token (or password) |

Pinned tooling: `goreleaser/goreleaser-action@v6.3.0` + GoReleaser CLI `v2.9.0`.

## Cut a release

```bash
git checkout main
git pull origin main
git tag -a v1.1.1 -m "SentinelFlow v1.1.1"
git push origin v1.1.1
```

Watch the **Release** workflow. On success:

- GitHub Release `v1.1.1` includes binaries + `checksums.txt` (primary install path)
- If Docker Hub secrets are present: `sentinelflow/sentinelflow:v1.1.1`, `:v1`, `:v1.1`, `:latest`
- Install path: `curl -fsSL …/scripts/install.sh | bash` (verifies checksums)

## Verify

```bash
VERSION=1.1.1 ./scripts/install.sh
./bin/sentinelflow version

# Optional — only if Docker Hub publish ran for this tag:
# docker pull sentinelflow/sentinelflow:v1.1.1
# docker run --rm sentinelflow/sentinelflow:v1.1.1 version
```

## Module path decision

**Supported install:** release binary (`install.sh`), GitHub Action, clone + `make build`. Docker is optional (local `docker build`, or Hub when secrets published an image).

**Not supported:** `go install`. The Go module path is `github.com/cozygarage/sentinelflow` while the GitHub repository is `cozyGarage/sentielflow`. Aligning those names is a deferred breaking change; until then, never advertise `go install`.

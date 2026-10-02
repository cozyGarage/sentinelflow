# Releasing SentinelFlow

GoReleaser publishes GitHub Release assets (`checksums.txt` + platform archives) on `v*` tags. Docker Hub images are published **only when** `DOCKER_USERNAME` / `DOCKER_PASSWORD` are set; otherwise the workflow uses `--skip=docker` so binaries still ship. Prefer install script / GitHub Release binaries over assuming a Hub `:latest` pull.

## Prerequisites

| Secret | Required? | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | Automatic | Create GitHub Release + upload assets |
| `DOCKER_USERNAME` | Optional | Docker Hub username for `sentinelflow/sentinelflow` |
| `DOCKER_PASSWORD` | Optional | Docker Hub access token (or password) |

Pinned tooling: `goreleaser/goreleaser-action` and GoReleaser CLI `v2.9.0` (SHA-pinned in the workflow). Workflows also pin `actions/*` by commit SHA; Dependabot updates `.github/dependabot.yml`.

## Cut a release

```bash
git checkout main
git pull origin main
git tag -a v1.2.0 -m "SentinelFlow v1.2.0"
git push origin v1.2.0
```

Watch the **Release** workflow. On success:

- GitHub Release `v1.2.0` includes binaries + `checksums.txt` (primary install path)
- Keyless Cosign signatures: `checksums.txt.sig` + `checksums.txt.pem`
- SLSA provenance attestation on `checksums.txt`
- CycloneDX + SPDX SBOMs and an artifact self-scan report
- If Docker Hub secrets are present: `sentinelflow/sentinelflow:v1.2.0`, `:v1`, `:v1.1`, `:latest`

## Verify

```bash
VERSION=1.2.0 ./scripts/install.sh
./bin/sentinelflow version

# Optional — verify checksums.txt with Cosign (needs cosign + the .sig/.pem assets):
# VERIFY_SIGNATURE=1 VERSION=1.2.0 ./scripts/install.sh

# Optional — only if Docker Hub publish ran for this tag:
# docker pull sentinelflow/sentinelflow:v1.2.0
# docker run --rm sentinelflow/sentinelflow:v1.2.0 version
```

The release workflow runs `scan-artifact` on the published Linux binary (`--fail-on critical`) and attaches `artifact-scan.json`.

## Module path decision

**Supported install:** release binary (`install.sh`), GitHub Action, clone + `make build`. Docker is optional (local `docker build`, or Hub when secrets published an image).

**Not supported:** `go install`. The Go module path is `github.com/cozygarage/sentinelflow` while the GitHub repository is `cozyGarage/sentielflow`. Aligning those names is a deferred breaking change; until then, never advertise `go install`.

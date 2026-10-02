# Scanner Implementation Details

This guide explains how each scanner in SentinelFlow v1.0 works.

## 1. Secret Scanner (`internal/scanner/secrets`)

### Detection

1. **Regex matching** — Patterns for AWS, GCP, GitHub, Stripe, OpenAI, Anthropic, Hugging Face, DigitalOcean, Cloudflare, and other common credential formats.
2. **Entropy analysis** — Shannon entropy threshold (default `4.5`) for high-randomness strings.
3. **Keyword prefilter** — For patterns that embed keywords (generic secrets, AWS secret key assignments, etc.), the line must contain a keyword before the regex runs.
4. **Deduping** — One secret value at a location is reported once (named provider beats generic/entropy).
5. **Magic-byte skip** — ELF/PE/Mach-O/archives are skipped here; the artifacts scanner handles binaries.
6. **Custom patterns** — Optional `.sentinelflow/patterns.yaml` under the **scan root** (not process CWD), plus optional regex strings in `scanners.secrets.patterns`.
7. **Live verify** — `--verify-secrets` / `scanners.secrets.verify` (network, off by default).

### Git history

When `scan_git_history` or `git.scan_history` is enabled, the scanner walks recent commits with `git log -p` and scans **added patch lines** only (not full historical blobs). Findings are deduplicated across commits. With `--diff-base`, history is limited to `base..HEAD`.

### Concurrency

Uses a fixed worker pool (`scanners.secrets.concurrency`, default 10; falls back to `scanners.concurrency`).

### Redaction

Findings mask secret values in snippets using the shared `redact` package — reports never echo raw credentials.

---

## 2. IaC Scanner (`internal/scanner/iac`)

### Frameworks

| Framework | Files | Checks |
| --- | --- | --- |
| Terraform | `.tf` | Public S3 ACLs, open security groups, unencrypted RDS, etc. |
| Kubernetes | `.yaml`, `.yml` | Privileged containers, root users, host namespaces, wildcard RBAC |
| Dockerfile | `Dockerfile`, `*.dockerfile` | Root user, `latest` tags, curl-to-bash, missing HEALTHCHECK |

### Implementation

- **Terraform**: per-resource parsing for S3 encryption/public-block and multi-line security group ingress (SSH/RDP open to the world)
- **Kubernetes**: multi-document YAML, `initContainers` / `ephemeralContainers`, pod-level `securityContext` inheritance, CronJob templates
- **Dockerfile**: instruction parsing with line continuations, case-insensitive commands, final-stage `USER` / `HEALTHCHECK` checks

Config knobs:

- `scanners.iac.frameworks` — enable only selected frameworks (`terraform`, `kubernetes`, `dockerfile`, …)
- `scanners.iac.skip_rules` — suppress findings by rule ID
- `scanners.iac.severity` — minimum severity gate


---

## 3. Dependency Scanner (`internal/scanner/dependencies`)

### Data source

Queries the [OSV API](https://osv.dev/) (`/v1/querybatch`, retries, on-disk cache) for Go, npm, pip, Maven, Cargo, and RubyGems ecosystems (auto-detected from lockfiles and manifests). Results are cached on disk for 24h (`$XDG_CACHE_HOME/sentinelflow/vulndb`; override with `SENTINELFLOW_CACHE_DIR`). Fully offline scanning is not supported yet.

### Supported files

Dependencies **prefer lockfiles when present** (`package-lock.json`, `npm-shrinkwrap.json`, classic `yarn.lock`, `go.sum`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `Gemfile.lock`, etc.). Range-only manifests without a lockfile are **best-effort** and may query approximate versions against OSV.

| Ecosystem | Manifests / lockfiles |
| --- | --- |
| Go | `go.mod` (+ `go.sum` when present) |
| npm | `package-lock.json` / `npm-shrinkwrap.json` / classic `yarn.lock` (preferred), `package.json` fallback |
| Python (PyPI) | `poetry.lock` / `Pipfile.lock` (preferred), `requirements.txt`, `pyproject.toml` |
| Maven | `pom.xml` (resolves basic `${property}` versions) |
| Cargo | `Cargo.lock` (preferred), `Cargo.toml` fallback |
| RubyGems | `Gemfile.lock` only (bare `Gemfile` unsupported) |

Unpinned or URL-based Python/Cargo requirements without a concrete version are skipped so OSV queries stay meaningful.


### Filtering

- Minimum severity from config (`scanners.dependencies.severity`)
- `ignore_dev` to skip dev dependencies
- `ignore_cves` — accepts CVE, GHSA, GO-, and OSV IDs

---

## 4. SAST Scanner (`internal/scanner/sast`)

OWASP-oriented regex rules for SQL injection, XSS, path traversal, SSRF, and command injection. Rules load from embedded `rules.yaml` (schema v2: `languages`, `paths`, `pattern-not`, `cwe`, `owasp`, `confidence`) so self-scan does not match detector text.

**Languages with shared sinks today:** Go, JavaScript/TypeScript, Python, Java. Other extensions are not claimed until language-specific rules exist.

A native Go AST pass flags `exec.Command` and SQL `Query`/`Exec`/`QueryRow`/`Prepare` with non-constant arguments. For well-typed Go modules, an SSA pass tracks request, environment, and HTTP response values through branches and direct calls into shell execution.

**Config:** `scanners.sast.severity` and `skip_rules` are honored (same behavior as IaC). Default concurrency is 8 workers.

**Limits:** Go dataflow currently covers selected request/environment/HTTP sources and `os/exec` shell sinks; dynamic dispatch and other source/sink families are not covered. Without a Go module, cached dependencies, or successful type checking, only the AST and regex checks run. SSA loading never downloads modules. Use the Semgrep adapter (`scanners.external.semgrep.mode: auto`) for broader coverage. Prefer `skip_rules` / `sentinelflow:ignore` / baseline for known noise.

---

## 5. Container Scanner (`internal/scanner/container`)

Wraps [Trivy](https://github.com/aquasecurity/trivy) when installed. Enable with `--container` and optionally `--container-image`. A filesystem path uses `trivy fs`. There is also an optional `trivy_fs` external adapter. Used in CI via the composite action with `scan-container: true`.

---

## 6. License Scanner (`internal/scanner/license`)

**Opt-in only** — enable with `--license` or `scanners.license.enabled: true`. Not part of `--all` / Action `scan-all`.

Checks `package.json`, npm v2/v3 lockfile license metadata, and `go.mod`. Flags:

- Licenses on the **denied** list (default GPL-3.0, AGPL-3.0, SSPL-1.0), and
- Licenses **not** on `scanners.license.allowed` when that list is non-empty.

Transitive licenses come from npm v2/v3 `package-lock.json` metadata when present, plus a **small hardcoded map** for Go and npm dependencies. Unknown or absent lockfile license metadata is not flagged; this is still not a full license DB or SBOM. Cargo/Ruby manifests are not scanned.

---

## 7. Policy Engine (`internal/scanner/policy`)

### OPA integration

The engine embeds Open Policy Agent. At scan time it:

1. Loads `.rego` files from `policies/` and configured globs
2. Collects Kubernetes manifests and Terraform resources as OPA input
3. Evaluates each policy and converts violations to findings

### Built-in policies (`policies.builtin`)

| Policy | Description |
| --- | --- |
| `no-public-s3-buckets` | Blocks public S3 ACLs and missing public access blocks |
| `no-privileged-containers` | Denies privileged K8s containers (app/init/ephemeral) and missing `runAsNonRoot` |
| `require-https` | Ensures TLS on ingress and load balancers |
| `enforce-encryption` | Requires encryption at rest for S3, RDS, EBS, EFS |

Embedded in the binary; project `.rego` files with the same name override.

### CLI

```bash
sentinelflow policy validate policies/my.rego
sentinelflow policy test policies/my.rego test/fixtures/policy/k8s-privileged-pod.json
```

See [Policy Authoring](policies.md) for Rego examples. Sample inputs live under `test/fixtures/`.

---

## 8. SBOM (`internal/scanner/sbom`)

Generates CycloneDX or SPDX JSON via `sentinelflow sbom` from `go.mod`, npm lockfiles, `Cargo.lock` (with versions), `poetry.lock`, and `Gemfile.lock`. `sentinelflow scan --sbom file.cdx.json` queries OSV for listed components.

---

## 9. Artifact scanner (`internal/scanner/artifacts`)

Opt-in (`--artifacts` / `sentinelflow scan-artifact`). Classifies files by magic bytes, unpacks archives with zip-slip / zip-bomb guards, catalogs Go buildinfo / JAR / wheel / npm / dpkg / apk components into the shared OSV matcher, extracts printable strings for secret matching, and runs ELF/PE/Mach-O hardening checks. Malware heuristics and YARA are opt-in (`checks: [malware]` / `scanners.external.yara`).

Nested members use `Location.ArtifactPath` (for example `app.war!/WEB-INF/lib/x.jar!/pom.properties`).

---

## 10. External adapters (`internal/adapter/external`)

Optional PATH tools: Semgrep, gitleaks, Grype, Syft, Trivy `fs`, YARA. Mode `auto` (warn if missing), `required` (error), or `off` (default).

---

## Unsupported / not in this release

- **AI code review** — Config and `--ai` flag exist for forward compatibility; enabling them is rejected until the scanner ships.
- **CloudFormation** — **Not planned** for now. Listing it under `scanners.iac.frameworks` fails config validation. Defaults are terraform, kubernetes, and dockerfile only.
- **Dynamic malware detonation** — Heuristics and optional YARA only; no sandbox execution.

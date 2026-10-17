# Scanner Implementation Details

This guide explains how each scanner in SentinelFlow works.

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

When `git.scan_history` is enabled (the deprecated `secrets.scan_git_history` also works), the scanner walks recent commits with `git log -p` and scans **added patch lines** only (not full historical blobs). Findings are deduplicated across commits. With `--diff-base`, history is limited to `base..HEAD`.

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
| GitHub Actions | `.github/workflows/*.y(a)ml` | Actions not pinned to a commit SHA, untrusted `${{ github.event.* }}` in `run:`/`github-script`, PR head checked out under `pull_request_target`/`workflow_run`, `write-all` or default token permissions |
| Docker Compose | `docker-compose*.y(a)ml`, `compose*.y(a)ml` | `privileged`, host network/PID/IPC, `SYS_ADMIN`/`ALL` capabilities, mounted `docker.sock` |

### Implementation

- **Terraform**: parsed with `hashicorp/hcl/v2` (`internal/scanner/tfparse`, shared with the OPA policy input). Per-resource checks cover S3 encryption/public-block and security group ingress (SSH/RDP open to the world). References such as `aws_s3_bucket.x[0].id` resolve to the resource
- **GitHub Actions / Compose**: YAML node walk, so findings carry the exact line. First-party `actions/*` unpinned refs are `low`, everything else `medium`+
- **Kubernetes**: multi-document YAML, `initContainers` / `ephemeralContainers`, pod-level `securityContext` inheritance, CronJob templates
- **Dockerfile**: instruction parsing with line continuations, case-insensitive commands, final-stage `USER` / `HEALTHCHECK` checks

Config knobs:

- `scanners.iac.frameworks` — enable only selected frameworks (`terraform`, `kubernetes`, `dockerfile`, …)
- `scanners.iac.skip_rules` — suppress findings by rule ID
- `scanners.iac.severity` — minimum severity gate


---

## 3. Dependency Scanner (`internal/scanner/dependencies`)

### Data source

Queries the [OSV API](https://osv.dev/) (`/v1/querybatch`, retries, on-disk cache) for Go, npm, pip, Maven (incl. Gradle lockfiles), Cargo, RubyGems, Composer (Packagist), and NuGet ecosystems (auto-detected from lockfiles and manifests). Results are cached on disk for 24h (`$XDG_CACHE_HOME/sentinelflow/vulndb`; override with `SENTINELFLOW_CACHE_DIR`). For air-gapped CI, see [offline scanning](usage.md#offline-scanning).

### Supported files

Dependencies use lockfiles where supported (`package-lock.json`, `npm-shrinkwrap.json`, classic `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `Gemfile.lock`, etc.). Go defaults to declared `go.mod` requirements; `go.sum` is checksum evidence, and selected graph resolution is opt-in. Range-only manifests without a lockfile are **best-effort** and may query approximate versions against OSV.

| Ecosystem | Manifests / lockfiles |
| --- | --- |
| Go | Declared `go.mod` requirements by default; opt-in selected module graph with `scanners.dependencies.go_module_graph` |
| npm | `package-lock.json` / `npm-shrinkwrap.json` / classic `yarn.lock` / `pnpm-lock.yaml` v5–v9 (preferred), `package.json` fallback |
| Python (PyPI) | `poetry.lock` / `Pipfile.lock` (preferred), `requirements.txt`, `pyproject.toml` |
| Maven | `pom.xml` (resolves basic `${property}` versions) |
| Cargo | `Cargo.lock` (preferred), `Cargo.toml` fallback |
| RubyGems | `Gemfile.lock` only (bare `Gemfile` unsupported) |
| Gradle (Maven) | `gradle.lockfile` (enable [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html)); test-only configurations count as dev |
| Composer (Packagist) | `composer.lock` (`packages-dev` count as dev; `dev-*` branches skipped) |
| NuGet | `packages.lock.json` (`RestorePackagesWithLockFile`) |

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

**Go taint (SSA, interprocedural and cross-file within the module):**

| Rule | Sink | CWE |
| --- | --- | --- |
| `go-ast-shell-tainted` | `exec.Command` with `sh -c` (request **or** environment input) | 78 |
| `go-ssa-sql-tainted` | `database/sql` `Query`/`Exec`/`Prepare`(…`Context`) query text | 89 |
| `go-ssa-path-tainted` | `os.Open`/`ReadFile`/`WriteFile`/`Create`/`Remove*`/`Mkdir*`, `http.ServeFile` | 22 |
| `go-ssa-ssrf-tainted` | `http.Get`/`Head`/`Post`/`PostForm`/`NewRequest*` URL | 918 |

Sources: every `*http.Request` field (`URL`, `Body`, `Header`, `Form`, …), `FormValue`/`PostFormValue`/`PathValue`/`Cookie`, `Header.Get`, `url.Values.Get`, gin (`c.Query`, `c.Param`, `c.PostForm`, …), echo (`c.QueryParam`, `c.Param`, `c.FormValue`, …), chi `URLParam`, gorilla `mux.Vars`. Environment variables (`os.Getenv`) only feed the shell rule, because they're operator-controlled. Sanitizers: `strconv.Atoi`/`Parse*`, `filepath.Base`/`path.Base`. Flow through helper functions is summarised per parameter, so a helper that returns a tainted argument doesn't taint unrelated call sites. When a query is proven tainted, the syntactic `go-ast-sql-nonconst` on the same line is dropped.

**Limits:** dynamic dispatch through interfaces you define is not followed (unknown calls propagate their arguments' taint conservatively), and fields of your own structs are tracked per allocation site, not per field. Without a Go module, cached dependencies, or successful type checking, only the AST and regex checks run. SSA loading never downloads modules. Use the Semgrep adapter (`scanners.external.semgrep.mode: auto`) for broader coverage. Prefer `skip_rules` / `sentinelflow:ignore` / baseline for known noise.

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

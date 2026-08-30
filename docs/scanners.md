# Scanner Implementation Details

This guide explains how each scanner in SentinelFlow v1.0 works.

## 1. Secret Scanner (`internal/scanner/secrets`)

### Detection

1. **Regex matching** — Patterns for AWS, GCP, GitHub, Stripe, and other common credential formats.
2. **Entropy analysis** — Shannon entropy threshold (default `4.5`) for high-randomness strings.
3. **Keyword prefilter** — For patterns that embed keywords (generic secrets, AWS secret key assignments, etc.), the line must contain a keyword before the regex runs.
4. **Custom patterns** — Optional `.sentinelflow/patterns.yaml` under the **scan root** (not process CWD), plus optional regex strings in `scanners.secrets.patterns`.

### Git history

When `scan_git_history` or `git.scan_history` is enabled, the scanner walks recent commits with `git log -p` and scans **added patch lines** only (not full historical blobs). Findings are deduplicated across commits.

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

Queries the [OSV API](https://osv.dev/) for Go, npm, pip, Maven, and Cargo ecosystems (auto-detected from lockfiles and manifests).

### Supported files

Dependencies **prefer lockfiles when present** (`package-lock.json`, `npm-shrinkwrap.json`, classic `yarn.lock`, `go.sum`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, etc.). Range-only manifests without a lockfile are **best-effort** and may query approximate versions against OSV.

| Ecosystem | Manifests / lockfiles |
| --- | --- |
| Go | `go.mod` (+ `go.sum` when present) |
| npm | `package-lock.json` / `npm-shrinkwrap.json` / classic `yarn.lock` (preferred), `package.json` fallback |
| Python (PyPI) | `poetry.lock` / `Pipfile.lock` (preferred), `requirements.txt`, `pyproject.toml` |
| Maven | `pom.xml` (resolves basic `${property}` versions) |
| Cargo | `Cargo.lock` (preferred), `Cargo.toml` fallback |

Unpinned or URL-based Python/Cargo requirements without a concrete version are skipped so OSV queries stay meaningful.


### Filtering

- Minimum severity from config (`scanners.dependencies.severity`)
- `ignore_dev` to skip dev dependencies
- `ignore_cves` — accepts CVE, GHSA, GO-, and OSV IDs

---

## 4. SAST Scanner (`internal/scanner/sast`)

OWASP-oriented regex rules for SQL injection, XSS, path traversal, SSRF, and command injection. Rules load from embedded `rules.yaml` (not Go string literals) so self-scan does not match detector text.

**Languages with shared sinks today:** Go, JavaScript/TypeScript, Python, Java. Other extensions are not claimed until language-specific rules exist.

**Config:** `scanners.sast.severity` and `skip_rules` are honored (same behavior as IaC). Default concurrency is 8 workers.

**Limits:** line-local regex only — no taint/dataflow. Prefer `skip_rules` / baseline for known noise rather than disabling the scanner.

---

## 5. Container Scanner (`internal/scanner/container`)

Wraps [Trivy](https://github.com/aquasecurity/trivy) when installed. Enable with `--container` and optionally `--container-image`. Used in CI via the composite action with `scan-container: true`.

---

## 6. License Scanner (`internal/scanner/license`)

**Opt-in only** — enable with `--license` or `scanners.license.enabled: true`. Not part of `--all` / Action `scan-all`.

Checks `package.json` and `go.mod` only. Flags:

- Licenses on the **denied** list (default GPL-3.0, AGPL-3.0, SSPL-1.0), and
- Licenses **not** on `scanners.license.allowed` when that list is non-empty.

Transitive dependency licenses come from a **small hardcoded map** (not a full license DB or SBOM). Unknown packages are not flagged. Cargo/Ruby manifests are not scanned.

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

Generates CycloneDX JSON via `sentinelflow sbom` from `go.mod`, `package-lock.json`, and `Cargo.lock` (missing files skipped; corrupt lockfiles fail).

---

## Unsupported / not in this release

- **AI code review** — Config and `--ai` flag exist for forward compatibility; enabling them is rejected until the scanner ships.
- **CloudFormation** — **Not planned** for now. Listing it under `scanners.iac.frameworks` fails config validation. Defaults are terraform, kubernetes, and dockerfile only.

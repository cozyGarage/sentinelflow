# Configuration Reference

SentinelFlow reads `.sentinelflow.yaml` from the **scan target directory** (the path passed to `scan` / `baseline` / `sbom`), falling back to the process working directory. Use `--config` to force an explicit file. Environment variables prefixed with `SENTINELFLOW_` can override file values.

Relative `baseline.file` paths are resolved against the scan target as well.

Run `sentinelflow init` to generate a starter configuration.

## Top-Level Options

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `version` | string | `"1.0"` | Configuration schema version |
| `scan_timeout` | string | `"10m"` | Overall scan deadline (Go duration). Overridable with `--timeout` |

## Scanners

### Global (`scanners`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `concurrency` | int | `8` | Default worker concurrency for file scanners |
| `exclude` | []string | `test/**`, `**/testdata/**` | Global path globs skipped by the engine walk (all scanners). Prefer this over stuffing skips into the secrets allowlist. |

### Secrets (`scanners.secrets`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable secret scanning |
| `allowlist` | []string | test file globs | Glob patterns skipped **only** by the secrets scanner (does not hide paths from IaC/SAST) |
| `patterns` | []string | — | Extra secret **regex** patterns (compiled as Go RE2). Invalid regexes are skipped |
| `entropy_threshold` | float | `4.5` | Minimum Shannon entropy to flag |
| `scan_git_history` | bool | `false` | Scan git history for secrets |
| `max_history_depth` | int | `50` | Max commits to scan in history |

### IaC (`scanners.iac`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable IaC scanning |
| `frameworks` | []string | terraform, kubernetes, dockerfile | Frameworks to scan. Unknown names (including CloudFormation) fail config validation. CloudFormation is **not planned** / unsupported |
| `severity` | string | `medium` | Minimum severity to report |
| `skip_rules` | []string | — | Rule IDs to ignore |

### Dependencies (`scanners.dependencies`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable dependency scanning |
| `ecosystems` | []string | `["auto"]` | Package ecosystems to scan |
| `severity` | string | `medium` | Minimum severity to report |
| `ignore_dev` | bool | `false` | Skip dev dependencies |
| `ignore_cves` | []string | — | CVE, GHSA, GO-, or OSV IDs to ignore |
| `fail_on_error` | bool | `true` | Fail the CLI when the dependencies scanner errors (e.g. OSV network blips). Set `false` to keep any findings and print a warning instead of failing solely for transport errors |

Default stays strict for security. Soft-fail is for flaky CI networks only — findings that were collected still go through `fail_on`.

When lockfiles are present (`package-lock.json`, `npm-shrinkwrap.json`, `go.sum`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, …), the scanner prefers them. Range-only manifests without a lockfile are best-effort / may query approximate versions.

### SAST (`scanners.sast`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable SAST scanning |
| `severity` | string | `medium` | Minimum severity to report (`critical`/`high`/`medium`/`low`) |
| `skip_rules` | []string | — | Rule IDs (or finding IDs) to ignore |
| `concurrency` | int | `8` | Worker pool size for file scanning |

Built-in rules: `sqli-concat`, `sqli-format`, `xss-innerhtml`, `xss-eval`, `xss-dangerously`, `path-traversal`, `path-join-user`, `ssrf-http`, `cmd-inject-exec`, `cmd-inject-shell`.

### Container (`scanners.container`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable container scanning (requires Trivy) |
| `image` | string | — | Container image reference |
| `severity` | string | `high` | Minimum severity to report |

### License (`scanners.license`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Opt-in license policy scanning (`package.json` / `go.mod` only). Not enabled by `--all` |
| `denied` | []string | GPL-3.0, AGPL-3.0, SSPL-1.0 | Licenses that fail the scan |
| `allowed` | []string | — | If non-empty, only these licenses are permitted (checked before denied) |

License coverage is intentionally limited: known transitive licenses are a small hardcoded map, not a full SBOM license database. Keep license **off** unless you explicitly want this limited gate.

### Baseline (`baseline`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Filter findings against a baseline file |
| `file` | string | `.sentinelflow/baseline.yaml` | Baseline file path |

### AI (`scanners.ai`)

AI-powered code review is **planned** and not available in this release. Setting `enabled: true` or passing `--ai` is rejected with a clear error. Config fields are retained for forward compatibility.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Must remain `false` (rejected if `true`) |
| `provider` | string | `openai` | Reserved for a future release |
| `model` | string | `gpt-4` | Reserved for a future release |
| `api_key` | string | env | Reserved (`SENTINELFLOW_AI_API_KEY` / `OPENAI_API_KEY`) |
| `focus` | []string | injection, auth, crypto | Reserved focus areas |

## Policies (`policies`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable policy scanning |
| `files` | []string | `policies/*.rego`, `.sentinelflow/policies/*.rego` | Custom policy file globs |
| `builtin` | []string | see defaults | Documented built-in policy names (loaded from `policies/`) |

Built-in policies:

- `no-public-s3-buckets`
- `no-privileged-containers`
- `require-https`
- `enforce-encryption`

## Reporting (`reporting`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `format` | string | `text` | Default output format (`--format` / `-f` overrides) |

Supported formats: `text`, `json`, `sarif`, `markdown`, `html`. Remediation text is always included when present on a finding. GitHub annotations and SARIF upload are workflow/Action concerns, not config knobs.

## Fail Conditions (`fail_on`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `severity` | string | `high` | Fail threshold: `critical`, `high`, `medium`, or `low` |
| `secrets` | bool | `true` | Fail on any secret finding |
| `policy_violations` | bool | `true` | Fail on policy violations |

CLI override: `--fail-on high`

## Git (`git`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `scan_history` | bool | `false` | Scan git commit history |
| `history_depth` | int | `50` | Number of commits to scan |

## Example

```yaml
version: "1.0"

scanners:
  # Optional global worker-pool size for file-based scanners (default: 8).
  # Per-scanner overrides: secrets.concurrency, sast.concurrency, iac.concurrency.
  concurrency: 8
  exclude:
    - "test/**"
    - "examples/demo-project/**"
  secrets:
    enabled: true
    entropy_threshold: 4.5
    allowlist:
      - "**/*_test.go"

  iac:
    enabled: true
    frameworks:
      - terraform
      - kubernetes
      - dockerfile

  dependencies:
    enabled: true
    ecosystems:
      - auto
    severity: medium
    # fail_on_error: false  # optional: soft-skip OSV/network errors (default true)

policies:
  enabled: true
  builtin:
    - no-public-s3-buckets
    - no-privileged-containers

fail_on:
  severity: high
  secrets: true
  policy_violations: true
```

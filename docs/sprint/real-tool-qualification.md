# Real tool qualification matrix

Status: **SC-095 availability boundary recorded; six optional integrations remain unqualified**. Local and hosted inventories were refreshed on 2026-10-17. Exact-head hosted CI run [39049882098](https://github.com/cozyGarage/sentinelflow/actions/runs/39049882098) ran pinned govulncheck fixtures and the availability inventory on `linux/amd64`, Go `go1.27.2`.

The deterministic fake-executable checks validate SentinelFlow's control flow and parsing. They do not qualify the behavior of installed upstream binaries. Both local `which` and the hosted `command -v` inventory found no standalone binaries for Semgrep, Gitleaks, Grype, Syft, Trivy, YARA, or govulncheck. The pinned govulncheck qualification below uses Go's module installer and passed locally and in hosted CI. The six external scanner integrations remain unqualified as permitted by SC-095's acceptance criterion.

| Tool | Adapter invocation in this checkout | Version evidence | Clean / finding / operational observations |
| --- | --- | --- | --- |
| Semgrep | `semgrep --config=auto --json --quiet <path>` | Missing on PATH; no version observed. | Not run; unqualified. |
| Gitleaks | `gitleaks detect --source <path> --report-format json --no-banner --exit-code 0` | Missing on PATH; no version observed. | Not run; unqualified. |
| Grype | `grype <path> -o json` | Missing on PATH; no version observed. | Not run; unqualified. |
| Syft | `syft <path> -o json` | Missing on PATH; no version observed. | Not run; unqualified. |
| Trivy filesystem | `trivy fs --format json --quiet <path>` | Missing on PATH; no version observed. | Not run; unqualified. |
| YARA | `yara -r <rules-or-dot> <path>` | Missing on PATH; no version observed. | Not run; unqualified. |

## Adapter command contract (SC-031)

The repository currently declares these invocations. `--version` is the stored probe metadata; the adapter does not execute version probes yet, so these are not observed versions. A successful process exit is `0` for every adapter; Gitleaks is explicitly passed `--exit-code 0` so findings do not use the process status. Any other exit is currently an operational failure. JSON adapters require non-empty, parseable output with the tool-specific collection/envelope; YARA uses line-oriented text and permits empty output as a clean no-match result. Installed upstream versions and their real clean/finding/error behavior remain unqualified.

| Adapter | Executable and arguments | Declared version probe | Output contract |
| --- | --- | --- | --- |
| Semgrep | `semgrep --config=auto --json --quiet <path>` | `semgrep --version` | Required JSON `results` collection; valid empty collection is clean. |
| Gitleaks | `gitleaks detect --source <path> --report-format json --no-banner --exit-code 0` | `gitleaks --version` | Required JSON array; valid empty array is clean. |
| Grype | `grype <path> -o json` | `grype --version` | Required JSON `matches` collection; valid empty collection is clean. |
| Syft | `syft <path> -o json` | `syft --version` | Required JSON `artifacts` collection; valid empty collection is clean. |
| Trivy filesystem | `trivy fs --format json --quiet <path>` | `trivy --version` | Required JSON schema/artifact identity; `Results` may be omitted for an empty report. |
| YARA | `yara -r <rules-or-dot> <path>` | `yara --version` | Line-oriented match output; empty output is allowed. Nonzero clean/no-match conventions have not been verified against an installed version. |

The command-argument and output requirement rows are asserted by `TestSC031_ExternalToolCommandContracts` and the SC-033 parser positive/negative controls. Fake executable regressions cover findings followed by operational failure and incomplete/empty required reports. They validate this wrapper's declared contract, not upstream compatibility.
| govulncheck | `govulncheck -json -C <module-dir> ./...` | Pinned `golang.org/x/vuln/cmd/govulncheck@v1.9.0`, Go `go1.27.2`; observed DB `file://` synthetic fixture. Standalone binary was unavailable; script invokes the pinned module version. | `bash scripts/qualify-govulncheck.sh` passed locally and in hosted SC-095 run [39049882098](https://github.com/cozyGarage/sentinelflow/actions/runs/39049882098). Called vulnerable function is reachable; imported-only and absent advisories remain unknown; missing `go.mod` returns an operational error and leaves reachability unknown. The test uses a local module proxy and local DB, with no live advisory dependency. |

The real govulncheck result confirms an important boundary: “imported but not called” cannot be inferred as unreachable from an absent govulncheck finding. The implementation must preserve unknown unless the tool emits a qualified negative observation. The repeatable local qualification is run by `bash scripts/qualify-govulncheck.sh`; CI runs that same script in the named SC-095 job.

The required evidence for each installed tool is its exact version, effective arguments, stdout/stderr treatment, process status for clean/finding/operational cases, and the resulting finding/error decision. Do not treat CI's pinned `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` vulnerability job as reachability qualification: it uses a different command and scans the SentinelFlow repository itself.

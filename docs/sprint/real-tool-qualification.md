# Real tool qualification matrix

Status: **govulncheck locally qualified against synthetic fixtures; other optional tools unqualified; hosted checks pending**. The local `PATH`/version inventory was refreshed on 2026-10-17 at branch head `5cc8f0d2a2299debe4ba6c707ec417510223c3ce` on `linux/amd64`, Go `go1.27.2`. The initial source audit was based at `cdd7cd7c390c65809fcd08e10dd0492360579565`.

The deterministic fake-executable checks validate SentinelFlow's control flow and parsing. They do not qualify the behavior of installed upstream binaries. The refreshed `command -v` inventory found no standalone binaries for Semgrep, Gitleaks, Grype, Syft, Trivy, YARA, or govulncheck; the pinned govulncheck qualification below was run through Go's module installer. The six external scanner integrations remain unqualified.

| Tool | Adapter invocation in this checkout | Version evidence | Clean / finding / operational observations |
| --- | --- | --- | --- |
| Semgrep | `semgrep --config=auto --json --quiet <path>` | Missing on PATH; no version observed. | Not run; unqualified. |
| Gitleaks | `gitleaks detect --source <path> --report-format json --no-banner --exit-code 0` | Missing on PATH; no version observed. | Not run; unqualified. |
| Grype | `grype <path> -o json` | Missing on PATH; no version observed. | Not run; unqualified. |
| Syft | `syft <path> -o json` | Missing on PATH; no version observed. | Not run; unqualified. |
| Trivy filesystem | `trivy fs --format json --quiet <path>` | Missing on PATH; no version observed. | Not run; unqualified. |
| YARA | `yara -r <rules-or-dot> <path>` | Missing on PATH; no version observed. | Not run; unqualified. |
| govulncheck | `govulncheck -json -C <module-dir> ./...` | Pinned `golang.org/x/vuln/cmd/govulncheck@v1.9.0`, Go `go1.27.2`; observed DB `file://` synthetic local fixture. | `bash scripts/qualify-govulncheck.sh` passed locally. A called vulnerable function is reachable; imported-only and absent advisories remain unknown; a real scan of a directory without `go.mod` returns an operational error and leaves reachability unknown. The test uses a local module proxy and local DB, with no live advisory dependency. Hosted SC-095 run pending. |

The real govulncheck result confirms an important boundary: “imported but not called” cannot be inferred as unreachable from an absent govulncheck finding. The implementation must preserve unknown unless the tool emits a qualified negative observation. The repeatable local qualification is run by `bash scripts/qualify-govulncheck.sh`; CI runs that same script in the named SC-095 job.

The required evidence for each installed tool is its exact version, effective arguments, stdout/stderr treatment, process status for clean/finding/operational cases, and the resulting finding/error decision. Do not treat CI's pinned `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` vulnerability job as reachability qualification: it uses a different command and scans the SentinelFlow repository itself.

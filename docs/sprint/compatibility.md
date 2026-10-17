# Scan-correctness compatibility notes

Status: **implementation notes in progress**. These notes describe the changes in the current scan-correctness worktree; they are not a release notice. The final revision and hosted evidence belong in [the acceptance report](scan-correctness-acceptance.md) when SC-099 runs.

## Dependency inventory

Go inventory now follows `require` entries parsed from `go.mod`. It no longer uses `go.sum` ordering to choose a selected version or treats checksum-only modules as resolved transitive dependencies. A missing or malformed `go.sum` therefore does not erase valid declared requirements. The dependencies scanner warns that workspace selection and replacements are not applied and that the inventory is not a resolved package graph. Consumers that previously relied on checksum-only entries may see fewer Go components; complete module/workspace resolution is outside this core and must not be implied by a clean result.

npm lockfiles retain each installation path, so the same name at two versions can produce separate OSV queries and findings. Dependency finding IDs now incorporate name, version and install path. Metadata includes the inventory source and install path; the location snippet also includes the installation path. Downstream dashboards that key only on finding ID or assumed one package/name row should expect distinct IDs and preserve the metadata when grouping.

## Baselines and fingerprints

New v2 baselines use the strong finding fingerprint and ID. Their historical line-sensitive hash is no longer used as an additional weak match when a fingerprint exists; otherwise a baseline for one package instance could suppress another instance with the same rule, file and title. Legacy entries without a fingerprint retain hash fallback. Existing v2 baselines with old fingerprints may leave newly distinct package-instance findings visible. Review those findings and update only intended entries; do not reset the whole baseline as a compatibility shortcut.

Line movement remains fingerprint-independent of source line numbers for findings whose identity inputs are unchanged. Dependency instance snippets are identity-bearing, so changing the installed version or lockfile location intentionally creates a new finding identity.

## Tool completion, reachability and CI exits

Structured-output adapters now reject missing tool result collections or report identity instead of interpreting `{}` as a clean scan. Trivy may omit `Results` when empty, so its JSON envelope requires a nonzero schema version and artifact name while allowing an absent results list; this follows the upstream [`Report` model](https://github.com/aquasecurity/trivy/blob/main/pkg/types/report.go), which marks `Results` optional in JSON. Semgrep's reported analysis errors make the report incomplete; any parsed findings are retained. Required mode returns the failure, while auto mode keeps findings and adds a warning. Gitleaks is invoked with `--exit-code 0` so finding presence is separate from process failure; these exact behaviors remain unqualified until pinned real binaries are exercised. Fake-tool checks do not establish upstream-version compatibility.

`Finding.Reachable` remains an optional pointer: `true` is qualified symbol evidence, `false` is a qualified package observation from a completed symbol-level run, and `nil` is unknown or unassessed. Unmatched advisories, unsupported scan levels, cancellation and malformed/incomplete streams do not become `false`. A required reachability failure remains a scanner error even when dependency lookup's optional error policy would otherwise soften a transport failure.

The CLI exit contract remains `0` for a clean accepted scan, `1` for a finding gate, `2` for operational/configuration failure, and `3` for a deadline. If the engine can return partial findings with an error, the CLI writes the report first and then returns the operational or timeout exit. Operational failure takes precedence over a simultaneous severity gate; a report is evidence of partial observations, not a successful scan.

## Evidence still required

These behaviors have deterministic local regressions in the current worktree. Hosted GitHub Actions have not run on the changes. Semgrep, Gitleaks, Grype, Syft, Trivy and YARA were absent from PATH and remain unqualified. Govulncheck v1.9.0 was separately exercised against a synthetic local database; see the [real-tool qualification matrix](real-tool-qualification.md). This local check does not replace hosted Actions evidence.

# Scan-correctness compatibility notes

Status: **core behavior and migration notes recorded; external tools remain unqualified where noted**. These notes describe the scan-correctness core and are not a release notice. Exact revision and hosted evidence are in [the acceptance report](scan-correctness-acceptance.md).

## Dependency inventory

The core decisions and regression links are explicit: declared Go version/provenance is covered by `TestSC011_...` through `TestSC014_...`; npm package-instance identity and ordering by `TestSC021_...` through `TestSC024_...`; command completion and output by `TestSC031_...` through `TestSC034_...`; unknown reachability by `TestSC041_...` through `TestSC044_...`; comparison validity and cleanup by `TestSC051_...` through `TestSC054_...`; and the CLI exit precedence by `TestSC091_...` through `TestSC093_...`. `go.mod` requirements are the supported Go fallback; `go.sum` is checksum evidence only. Exit precedence is clean `0`, finding gate `1`, operational/configuration failure `2`, deadline `3`; an operational/deadline result takes precedence over a simultaneous finding gate. These are narrow declared-inventory semantics, not a claim of complete transitive resolution.

Go inventory now follows `require` entries parsed from `go.mod`. It no longer uses `go.sum` ordering to choose a selected version or treats checksum-only modules as resolved transitive dependencies. A missing or malformed `go.sum` therefore does not erase valid declared requirements. The dependencies scanner warns that workspace selection and replacements are not applied and that the inventory is not a resolved package graph. Consumers that previously relied on checksum-only entries may see fewer Go components; complete module/workspace resolution is outside this core and must not be implied by a clean result.

npm lockfiles retain each installation path, so the same name at two versions can produce separate OSV queries and findings. Dependency finding IDs now incorporate name, version and install path. Metadata includes the inventory source and install path; the location snippet also includes the installation path. Downstream dashboards that key only on finding ID or assumed one package/name row should expect distinct IDs and preserve the metadata when grouping.

### Before and after examples

| Case | Before | After |
| --- | --- | --- |
| Go module checksums | A stale `example.com/lib v1.2.0` row in `go.sum` could be selected ahead of `require example.com/lib v1.4.0`; checksum-only modules could look like resolved transitives. | `go.mod` `require` declarations are inventory evidence, so the declared `v1.4.0` is retained regardless of sum ordering. Checksum-only entries are not represented as a resolved graph. |
| npm duplicate installs | A name-keyed map collapsed `widget@1.2.0` and nested `widget@2.0.0` into one arbitrary component and query. | Each lockfile install path is retained and queried. Reports and fingerprints carry name, version and install path, so both instances can be reviewed independently. |
| Tool failure after output | Parseable findings followed by a nonzero process exit could be treated as successful analysis because findings existed; empty or malformed required output could look clean. | Findings are retained alongside the operational error. Required mode fails; auto mode warns and preserves findings. Required structured adapters reject empty/malformed reports, while valid explicit empty result collections are clean. |
| Bad comparison baseline | A failed, missing or incomplete base scan could still feed subtraction and suppress head findings. | Comparison rejects incomplete or non-comparable runs before subtraction, returns an operational error, and retains available head observations in the report. The CLI uses exit `2` (or `3` for a deadline), not the finding-only exit `1`. |

### API, fingerprint and baseline effects

The public `Finding` shape remains compatible; npm identity is carried in existing metadata/location fields and contributes to the generated finding ID/fingerprint. Consumers that aggregate by package name alone must now preserve multiple records. Go inventory semantics narrow to declared requirements where full selected graph resolution is unavailable; consumers must not infer transitive completeness. Strong fingerprints prevent a legacy weak hash from suppressing a distinct package instance; old baselines still load, but entries without fingerprints use legacy hash fallback. Review newly visible instances individually and update only intended baseline entries; do not regenerate baselines wholesale. Comparison errors remain operational failures even when a partial report is written.

## Baselines and fingerprints

New v2 baselines use the strong finding fingerprint and ID. Their historical line-sensitive hash is no longer used as an additional weak match when a fingerprint exists; otherwise a baseline for one package instance could suppress another instance with the same rule, file and title. Legacy entries without a fingerprint retain hash fallback. Existing v2 baselines with old fingerprints may leave newly distinct package-instance findings visible. Review those findings and update only intended entries; do not reset the whole baseline as a compatibility shortcut.

Line movement remains fingerprint-independent of source line numbers for findings whose identity inputs are unchanged. Dependency instance snippets are identity-bearing, so changing the installed version or lockfile location intentionally creates a new finding identity.

## Tool completion, reachability and CI exits

Structured-output adapters now reject missing tool result collections or report identity instead of interpreting `{}` as a clean scan. Trivy may omit `Results` when empty, so its JSON envelope requires a nonzero schema version and artifact name while allowing an absent results list; this follows the upstream [`Report` model](https://github.com/aquasecurity/trivy/blob/main/pkg/types/report.go), which marks `Results` optional in JSON. Semgrep's reported analysis errors make the report incomplete; any parsed findings are retained. Required mode returns the failure, while auto mode keeps findings and adds a warning. Gitleaks is invoked with `--exit-code 0` so finding presence is separate from process failure; these exact behaviors remain unqualified until pinned real binaries are exercised. Fake-tool checks do not establish upstream-version compatibility.

`Finding.Reachable` remains an optional pointer: `true` is qualified symbol evidence, `false` is a qualified package observation from a completed symbol-level run, and `nil` is unknown or unassessed. Unmatched advisories, unsupported scan levels, cancellation and malformed/incomplete streams do not become `false`. A required reachability failure remains a scanner error even when dependency lookup's optional error policy would otherwise soften a transport failure.

The CLI exit contract remains `0` for a clean accepted scan, `1` for a finding gate, `2` for operational/configuration failure, and `3` for a deadline. If the engine can return partial findings with an error, the CLI writes the report first and then returns the operational or timeout exit. Operational failure takes precedence over a simultaneous severity gate; a report is evidence of partial observations, not a successful scan.

## Evidence still required

These behaviors have deterministic local regressions and named hosted regression rows. CI run [39049882098](https://github.com/cozyGarage/sentinelflow/actions/runs/39049882098) and security run [39049882006](https://github.com/cozyGarage/sentinelflow/actions/runs/39049882006) passed on implementation head `23e245da4be46e76a1fbfe2bc7b1e094e8f528dd`. Semgrep, Gitleaks, Grype, Syft, Trivy and YARA were absent from PATH and remain unqualified. Govulncheck v1.9.0 was separately exercised against a synthetic local database; see the [real-tool qualification matrix](real-tool-qualification.md). Fake executable tests validate SentinelFlow behavior, not compatibility with uninstalled upstream versions.

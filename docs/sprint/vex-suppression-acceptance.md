# VEX suppression follow-up acceptance

This implementation addresses SC-071–SC-075 from the follow-up backlog. It deliberately does not claim independent organizational approval of repository-authored exceptions; SC-076–SC-080 still cover retained evidence, inline scope, path identity and authority provenance.

## Behavior and compatibility

- Product matching now includes ecosystem and canonical package name. Supported PURL type mappings are documented in [configuration](../configuration.md).
- Maven group/artifact, scoped npm and percent-encoded package segments are parsed. Product PURLs with qualifiers/subpaths and unsupported/malformed types fail closed with a VEX load error because current finding records cannot verify those identity fields.
- VEX vulnerability `name` and `aliases` match finding CVE, RuleID, or OSV vulnerability aliases. OSV aliases are retained from advisory normalization through dependency finding metadata. Alias matching remains constrained to a matching package identity.
- Product-free statements and versionless product PURLs fail by default. Explicit `vex_allow_broad: true` authorizes global or any-version statements. This is repository-controlled configuration, not independent approval.
- `baseline.expires` is valid through the named UTC calendar day and expires at next midnight UTC. Invalid dates are expired and cannot suppress indefinitely; the current API does not yet report malformed/expired suppression reasons.

Existing broad or malformed VEX documents can now turn a scan into an operational error. Migrate them by adding supported product/version PURLs or explicitly opting into broad scope after review. Keep qualifiers and subpaths out of VEX product IDs until scanner findings carry matching fields.

## Regression evidence

Failing-first tests were added for cross-ecosystem isolation, missing ecosystem identity, Maven and scoped npm PURLs, qualifier/subpath rejection, invalid PURLs, explicit broad-scope policy, package-scoped alias matching, OSV alias propagation, and expiry before/at/after UTC midnight including a non-UTC clock. Configuration tests verify broad scope defaults off and can be explicitly enabled.

GitHub Actions has named selectors for SC-071 through SC-075. The full `go test ./...`, full `go test -race -count=1 ./...`, `go vet ./...`, `actionlint`, sprint-doc checker and its four positive/negative tests passed. All seven SC-071–SC-075 selector invocations passed through `scripts/run-go-test-selector.sh`'s zero-match guard. The live self-scan reported zero unsuppressed findings, two existing inline-suppressed fixed executable calls, and `partial` dependency coverage because the Go inventory currently uses `go.mod` requirements without resolving a full package graph. No clean-coverage claim is made.

Hosted evidence for implementation head `399f289bd169f3b64b3a8f8c87222bb2c4aa7f0b`: [CI / scan correctness matrix](https://github.com/cozyGarage/sentinelflow/actions/runs/39052708181) and [Security Scan](https://github.com/cozyGarage/sentinelflow/actions/runs/39052708253) completed successfully; `gh pr checks 58` reported 60 passed and zero failed checks. These results cover the implementation commit. The final documentation commit will receive fresh exact-head checks before merge.

The identity boundaries follow the [OpenVEX statement model](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) and [Package-URL component model](https://github.com/package-url/purl-spec), while this implementation supports only the explicitly listed product types and direct statement product PURLs.

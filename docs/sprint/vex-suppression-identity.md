# VEX suppression identity and scope

This documents SC-071–SC-075 implementation boundaries. OpenVEX defines a VEX statement as a product, vulnerability, status, and time relationship; vulnerability `name` plus `aliases` identifies the advisory, and product PURLs carry type, namespace/name, version, optional qualifiers and subpath. SentinelFlow currently consumes direct statement product `@id` PURLs and does not implement OpenVEX product inheritance from enclosing documents.

## Matching contract

- A VEX vulnerability name or alias must match the finding’s CVE, OSV rule ID, or retained vulnerability alias.
- A product-scoped statement must match both the package ecosystem and canonical package name. Maven PURLs map group/artifact to `group:artifact`; scoped npm names and percent-encoded segments are decoded before comparison.
- A present PURL version matches the finding version exactly. A versionless PURL is broad across versions for that package and requires `vex_allow_broad: true`.
- A product-free `not_affected` or `fixed` statement is global and requires `vex_allow_broad: true`.
- Invalid/unsupported PURLs fail VEX loading. Qualifiers and subpaths are rejected because dependency findings do not yet carry matching identity for them. They are never parsed and dropped before matching.
- Supported PURL types are `golang`, `npm`, `maven`, `pypi`, `cargo`, `nuget`, `gem`, and `composer`. This is not a claim of full conformance for all registered PURL types.

The broad-scope switch is an explicit local opt-in, not independent organizational approval. A repository author who can modify `.sentinelflow.yaml` can enable it. Protected policy ownership and authorization controls remain follow-up work (SC-080).

## Compatibility and migration

Existing VEX entries that omit products or omit a version now fail by default. Either add package/version PURLs or set `vex_allow_broad: true` after reviewing each broad exception. Invalid product identifiers that were silently ignored now fail scan processing. Findings must include ecosystem metadata for product-scoped matching; missing identity is retained as a finding. OSV aliases now flow into finding metadata so a GHSA/CVE alias can match its OSV record without suppressing another package.

PURLs containing query qualifiers or fragment subpaths currently fail closed. Adding support requires preserving and matching those attributes against scanner-produced finding identity, plus parser fixtures grounded in the [Package-URL specification](https://github.com/package-url/purl-spec) and [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

Baseline `expires: YYYY-MM-DD` remains valid through that UTC date and becomes expired at the next midnight UTC. Invalid expiry strings are treated as expired, so they cannot grant indefinite suppression. This retains findings but does not yet emit an expiry diagnostic; audit reasons and suppressed observations are SC-076 work.

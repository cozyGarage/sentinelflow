# Suppression audit and identity

This covers SC-076–SC-080. Suppression is represented as an observation attached to the scan result, rather than silently disappearing after filtering. Each record contains a stable fingerprint, rule ID, source (`inline`, `vex`, `baseline`, `diff`, or `baseline-ref`), a generic reason, and authority provenance. It does not retain file paths, snippets, metadata, or secret values. Counts are reconciled from the final findings plus retained observations; source-specific counts are subtotals.

`authority: repository` or `repository_ref` describes where the rule came from. It does not claim that an independent organization or reviewer approved it. Repository-controlled baseline/VEX/configuration remains self-attested until protected policy ownership and external approval are implemented.

## Inline directives

Directives are recognized in comment text on the finding line or immediately preceding line. Text inside quoted literals is ignored. Existing behavior remains the default for compatibility. With `strict_ignores: true`, an applicable wildcard (`*`/`all`) or a rule without a non-empty `-- reason` fails post-processing and does not suppress the finding. A specific rule with a reason remains permitted.

Inline source reads reject absolute, drive-qualified and parent-traversal paths. Symlinks resolving outside the scan root do not provide suppression content. This keeps a finding path from making the scanner read ignore directives from an unrelated file.

## Fingerprints and path identity

Fingerprint key fields use unambiguous JSON-array serialization. Dependency ecosystem, package name and version participate so two installed versions do not share identity. Paths are slash-normalized and lexically cleaned; line and column numbers remain excluded. This changes generated v2 fingerprints relative to previous releases. Legacy baselines still load, but old stored IDs/fingerprints may not match; review visible findings and update only intended entries. Do not wholesale reset a baseline as a shortcut. See [compatibility notes](compatibility.md).

## Verification boundary

Named GitHub Actions selectors cover each item. Acceptance requires focused local regressions, full Go tests, race suite, vet, actionlint, sprint-doc validation and final exact-head CI/security workflows. Public reports include only the redacted observation schema; they never serialize the removed finding itself. Organizational approval, signed policy sources and protected exception ownership remain unimplemented.

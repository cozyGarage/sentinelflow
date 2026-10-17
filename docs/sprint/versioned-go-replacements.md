# Versioned Go replacements

SC-016 extends opt-in selected Go module graphs to versioned `replace` directives. For a requirement such as `example.com/lib@v1.2.0` replaced by `example.com/fork/lib@v2.3.4`, SentinelFlow queries both coordinates. This retains advisories published for the declared module while also checking the module that supplies the replacement code.

The finding retains the declared package and version as its primary source attribution and includes `additional_advisory_coordinates` metadata for replacement identities. Duplicate advisory IDs from both queries produce one finding for the dependency instance. Local or unversioned replacements remain unresolved and fail graph resolution visibly; SC-017 defines their safe coverage behavior. Workspace replacements remain outside this slice.

This dual lookup is a conservative coverage choice: the replacement may be a fork with independent advisories, while existing records may still be keyed to the original module. It does not claim that the replacement is behaviorally equivalent to the original or that module metadata proves compiled artifact contents.

# Local Go replacement handling

SC-017 defines the selected-graph policy for local and unversioned `replace` targets: fail graph resolution visibly before invoking `go list`, emit no dependency with a fabricated registry version, and do not traverse or read the target directory. This applies to nested local paths, paths outside the scan root, and unversioned module-path targets.

The default non-graph inventory remains the declared `go.mod` requirements and does not claim to model replacement source. Users who need this mode can keep the graph opt-in disabled until local source inventory has a bounded, provenance-preserving design. Versioned module replacements are handled by the dual-coordinate policy in [Versioned Go replacements](versioned-go-replacements.md).

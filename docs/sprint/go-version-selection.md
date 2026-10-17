# Go module version and toolchain selection

SC-019 delegates Minimal Version Selection, `exclude` handling, module major-version path matching, and pseudo-version generation to the pinned/local Go command already used by opt-in graph resolution. SentinelFlow preserves the exact selected module path and version in inventory. Query adaptation removes the leading `v` used by Go module versions, while retaining the pseudo-version timestamp/hash and `/vN` path suffix.

The `go` and `toolchain` directives describe language/toolchain build context rather than package components. They do not create synthetic module queries. The Go command's selected module graph is the dependency inventory; actual compiler/runtime exposure requires toolchain or artifact evidence. Go's `toolchain` directive is a suggested command toolchain and is not itself a module in `go list -m all` ([Go toolchain reference](https://go.dev/doc/toolchain), [Go Modules Reference](https://go.dev/ref/mod)). OSV-Scanner similarly documents that it does not infer the toolchain version from `go.mod`'s `go` directive ([OSV-Scanner configuration](https://google.github.io/osv-scanner/configuration/)).

Unsupported or inconsistent selection still fails visibly through `go list`; SentinelFlow does not invent a next version, rewrite module paths, or infer compiler exposure from a directive.

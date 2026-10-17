# Go workspace resolution

SC-018 makes opt-in selected graph resolution honor a governing `go.work`. The scanner parses the workspace `use` list, validates every member's `go.mod`, invokes `go list -m -json -mod=readonly all` once for that workspace, and verifies the returned main module set against the declared members. Go treats workspace `use` modules as main modules and selects a workspace build list across them ([Go Modules Reference](https://go.dev/ref/mod)). A scan rooted at a workspace member's subdirectory discovers and applies its parent `go.work`.

Direct dependencies keep the source `go.mod`, line, and indirect marker from each declaring workspace member while using the single workspace-selected version. A selected dependency declared by multiple members is attributed to each member. Workspace transitive dependencies use the stable `go.work` path and line zero. This preserves scope without persisting temporary checkout paths as package identity.

Versioned `go.work` replacements use the existing dual-coordinate advisory lookup. Local or unversioned workspace replacements fail visibly under SC-017 policy; duplicate members, duplicate module paths, malformed workspace files, and a scan module absent from `use` also fail closed. Workspace resolution still describes module metadata, not build-platform or artifact contents.

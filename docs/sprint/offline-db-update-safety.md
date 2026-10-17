# Offline database update safety

SC-087 bounds OSV archive downloads to 2 GiB, total expanded advisory JSON to 1 GiB, individual decompressed advisory JSON files to 32 MiB, and the decompressed index to 512 MiB. The index limit applies on both write and read, including status inspection and query loading, so a gzip expansion cannot bypass the cap. These ceilings are guardrails, not ecosystem support guarantees; a legitimate export exceeding a ceiling fails visibly and preserves the prior snapshot.

Per-ecosystem updates are serialized. Each download and compressed index is written to a unique temporary file, and the completed index replaces the prior snapshot with an atomic rename. A failed download, archive parse, or index encode leaves the existing index untouched; temporary artifacts are removed. Readers opening the index during replacement see a complete old or new file. A source that already loaded an index continues using its in-memory snapshot until recreated.

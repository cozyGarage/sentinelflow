# Scan outcome and partial-result contract

This change adds optional `status` fields to `pkg/api.ScanResult` and `ScannerRun`. The field is additive: old JSON remains readable, and old consumers that ignore unknown fields remain compatible. A decoder must treat an absent status as **unknown/legacy**, never infer `complete` from an empty findings array. Consumers that make a gate decision should first require a recognized status and apply their configured failure policy.

| Status | Meaning | Gate implication |
| --- | --- | --- |
| `complete` | The configured analysis ran without known degradation. Zero findings is a valid clean result. | Findings policy may be evaluated. |
| `partial` | Analysis ran, but a warning or known coverage limitation means results may be incomplete. | Must remain visible; required-coverage policy should reject it. |
| `failed` | A scanner or post-processing stage failed. Findings collected before failure may still be retained. | Fail closed for that required stage. |
| `timed-out` | Scanner execution ended at its context deadline. | Fail closed; retained findings are positive evidence only. |
| `not-applicable` | Scanner was evaluated and does not apply to this target. | Does not imply that a relevant scanner passed. Currently reserved for producers that can prove applicability. |
| `skipped` | Scanner did not execute, such as an unavailable auto-mode tool, or no scanner was configured. | Never interpret as clean. |

An aggregate result is `timed-out` if a run timed out; otherwise it is `failed` if a required scanner or post-processing stage failed; it is `partial` if any remaining run degraded or skipped; `skipped` means no configured scanner ran; otherwise it is `complete`. Existing `Error` and `Warnings` fields remain intact. `fail_on_error: false` continues to soften dependency scanner errors at the CLI gate, but the outcome remains visible; required reachability errors remain fatal.

## Evidence retention paths

| Failure point | Findings retained in memory/result? | Report attempted? | Status/evidence |
| --- | --- | --- | --- |
| Scanner returns findings and error | Yes; scanner run carries error and `partial` (or `timed-out`). | Yes, CLI emits report before returning operational failure. | Per-scanner error/status plus aggregate status. |
| Optional external tool missing (`auto`) | No scanner findings; other scanners continue. | Yes. | Warning and per-run `skipped`; aggregate is `partial` when other analysis ran. |
| Required external tool missing/fails or report is malformed | Other scanner findings and adapter-parsed positive findings are retained. | Yes when the engine returns its result. | Per-run `failed`/`partial`, error remains fatal. |
| VEX, diff, or baseline post-processing fails | Findings collected up to that stage are returned with a synthetic `postprocess:<stage>` failed run. | Yes; CLI writes the partial report, then returns failure. | Aggregate `failed`. The findings may not include transformations from the failed stage. |
| Baseline-ref comparison fails | Current head findings are retained; failure run is appended. | Yes. | Aggregate `failed`. |
| Report formatting fails | In-memory result exists, but no selected report is available. | No usable report. | CLI returns a tool error; report failure is not represented inside that unrenderable report. |
| Report file write fails | In-memory result exists, but requested output is not persisted. | Formatting succeeded; write did not. | CLI returns a tool error. Users must treat missing output as absent evidence, not clean. |
| File collection fails/cancels before result construction | No `ScanResult` exists to report. | No. | Top-level CLI error/timeout. |

## Migration

1. Keep consuming existing findings, scanner errors, warnings, and exit codes during rollout.
2. Read `status` when present. Treat absent or unknown values as unknown and fail closed for mandatory policy until the producer is upgraded.
3. For a zero-finding success, require `status == "complete"`; an empty findings list by itself is insufficient.
4. For coverage policy, reject `partial`, `failed`, `timed-out`, and `skipped` unless the organization explicitly permits a named degradation. `not-applicable` requires a separate applicability policy.

The API currently reserves `not-applicable`; it is not synthesized from a zero-files scan. Per-scanner `off` configuration is omitted from `scanner_runs`, preserving existing run-list behavior; aggregate `skipped` is emitted when no scanner ran. A later schema revision may add declared/configured scanner inventory so disabled analyzers are explicit individually. This implementation does not claim complete coverage of excluded or unsupported input types.

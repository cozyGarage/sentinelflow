# Offline vulnerability database freshness

SC-082 adds an opt-in freshness gate for offline OSV lookups. Existing offline scans remain permissive unless strict freshness is configured. The default maximum age is 720 hours (30 days).

```yaml
scanners:
  dependencies:
    offline_require_fresh: true
    offline_max_age: 720h
```

The equivalent CLI is `sentinelflow scan --deps --require-fresh-offline-db --offline-max-age 720h`. The strict flag implies offline mode. It rejects a missing or corrupt index, legacy data with no acquisition time, and snapshots older than the configured limit. Exactly-at-limit data is accepted. Future acquisition timestamps are clamped to age zero to avoid clock skew causing false staleness. Failure output identifies the ecosystem and suggests `sentinelflow db update --ecosystems <ecosystem>`.

Strict freshness remains a required scan outcome even if `scanners.dependencies.fail_on_error` is false. This prevents a transport soft-fail convenience from converting a required local evidence policy into a successful CI gate. Refresh the database on a schedule before required offline scans. File modification time does not affect the decision.

This policy checks the acquisition time recorded when this tool downloaded its local OSV archive. It does not prove when OSV published the underlying data, and it does not establish online/offline semantic parity.

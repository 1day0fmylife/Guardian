# Bounded telemetry history retention

G-07 adds migration 008, an index on `(observed_at, id)`; it does not change
policy, credentials, grants, address ownership or telemetry API response shapes.
Fresh and upgrade migrations remain common to SQLite and PostgreSQL.

There is no automatic deletion by default. Choose an age from your operational
history/diagnostic SLA, then explicitly configure, for example:

```sh
GUARDIAN_TELEMETRY_RETENTION_AGE=720h
```

`0s` disables retention. Positive ages are between 24h and 87600h. The worker
runs on startup and hourly, with a 30-second context deadline and at most 1000
rows per pass. Large backlogs require repeated maintenance batches. Metrics
record completed operations, errors, latency and successful deletion counts.

Build `cmd/guardian-maintenance` for manual review/application. It uses
`GUARDIAN_DATABASE_URL` supplied through your protected environment file and
never prints database URLs, device identities or telemetry bodies. It uses the
existing schema and does not race/run migrations independently. The application
must have applied migrations first.

```sh
guardian-maintenance --before=2026-09-01T00:00:00Z --limit=1000
# Default is dry-run. Review candidates before applying:
guardian-maintenance --before=2026-09-01T00:00:00Z --limit=1000 --dry-run=false
```

Both modes return only before/candidates/deleted/dry_run. Limits 1–10000,
past cutoffs and valid RFC3339 timestamps are required. Cutoffs round down to
whole UTC seconds. Exact-cutoff rows and the newest second of records per device
(all ties) are preserved even if the device is offline and all samples are old.
This conservative rule avoids variable-width RFC3339 fraction ordering bugs
and retains the existing latest-telemetry/last-seen diagnostics. Server-generated
`observed_at` timestamps are UTC. The latest second is a retention exception,
not a promise that every old row is deleted.

Deletion and a `telemetry.retention` audit event (system actor, cutoff, limit,
actual deleted count) commit atomically. Dry-run neither deletes nor emits audit
mutations. Repeated batches are idempotent; cancellation/DB errors roll back.
Device state, WireGuard keys/ACLs, commands, last_seen and audit history are not
pruned. A failed retention operation cannot broaden service access.

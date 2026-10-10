# G-07 — production persistence, observability and test matrix

Baseline: main `0e12301d4f37` (merged G-06), checked against the ecosystem
plan dated 2026-10-10 and Guardian PLAN.md before implementation.

## Existing behavior reused

| Area | Baseline | G-07 change |
| --- | --- | --- |
| Persistence | Shared SQLite/PostgreSQL migrations; real PostgreSQL 16 CI service | Extend older core-store tests to both dialects; migration 008 index |
| Policy/RBAC | Versioned catalog, role permissions, explicit grants and deny precedence | Observe existing decisions without changing response fields or authorization |
| Revocation | Two-phase revocation and fail-closed gateway synchronization | Test persisted revocation through DB outage/reopen and gateway synchronization |
| WireGuard | Durable peer reconciliation, retry and confirmation | Count pass and peer outcomes without identities or errors in labels |
| Health | Existing liveness/readiness and structured logs | Separate private exporter, DB ping and optional gateway TCP probe |
| Telemetry | Ingestion and latest-observation view | Disabled-by-default audited retention, bounded batches and dry-run CLI |

No Redis authority, additional repository changes, replacement ACL engine,
upstream credentials in policy, or default access grants were introduced.

## Operational behavior

See [monitoring configuration](../deploy/monitoring/README.md) and
[telemetry retention](telemetry-retention.md). Metrics accept only a fixed
vocabulary of operations, service IDs, reasons and results. Unknown label
values are ignored. The exporter is opt-in and accepts literal loopback
addresses only; the public API still returns 404 for `/metrics`.
DB scrape failures return `guardian_database_up 0` without SQL/URL/error details.
A gateway probe checks TCP reachability, not TLS or application authorization.

Retention preserves the latest second (including ties) per device, even for
long-offline devices. It never changes lifecycle, credentials, grants or
last-seen state. An applied deletion and its system audit event commit together.
Preview has no deletion/audit side effect. Migration 008 adds only an index;
upgrade/repeat tests verify existing telemetry survives.

A revoking device may retain a management credential during peer removal.
The compatible response is `access_state: revoking` with `services: []`.
Tests preserve this contract rather than prematurely invalidating credentials.
Database failure cannot return an authorized cached policy; the gateway clears
service targets after its existing stale-snapshot deadline. Fresh snapshots
still contain zero targets after revocation and recovery.

## Validation (2026-10-10)

Passed locally against PostgreSQL 16-alpine and SQLite:

- `GUARDIAN_TEST_POSTGRES_URL=... go test ./...`
- `GUARDIAN_TEST_POSTGRES_URL=... go test -race ./...`
- `go vet ./...`
- `CGO_ENABLED=0 go build ./cmd/...`
- Added migration upgrade test: both dialects with race detector.
- Frontend: `bun run --cwd web test` (6 tests, 24 assertions) and build.
- `docker compose config --quiet` and `git diff --check`.
- Official `prom/prometheus:v3.5.0` promtool: configuration, five rules and
  synthetic DB/configured-gateway/disabled-gateway alert scenarios.

The existing backend CI supplies `GUARDIAN_TEST_POSTGRES_URL`; its `go test
./...` automatically executes the expanded matrix. No parallel workflow or
second PostgreSQL stack was added. Race and all-command builds were additionally
run locally. Remote CI results must be inspected on the PR after publication.

Automated recovery cases include terminating the active PostgreSQL backend
and reconnecting; closing/reopening the authoritative store through API and
real store-backed gateway synchronization; and a TCP endpoint closing and
returning on the same address. Policy tests cover denied/ungranted devices,
revocation, no secret/identity labels and absence of public exporter routes.
Existing RBAC, scope isolation and compatibility tests remain in the full suite.

A separate live smoke test used a local test-only PostgreSQL container and
running Guardian binary: pause DB -> `/readyz` 503, metrics DB up=0, no stale
allow policy; resume/restart DB -> readiness/metrics recover and revoked
service access stays empty. Maintenance binary preview reported candidates=2,
deleted=0; explicit apply deleted=2; repeated apply deleted=0.

This verifies single authoritative database outage/recovery, not promotion of
HA database replicas or multi-node fencing (deferred G-09). Gateway TCP tests
and logical ACL tests do not claim a new physical WireGuard acceptance run;
existing gateway deployment acceptance remains in CI. The unchanged frontend
build reports its existing >500 kB chunk advisory.

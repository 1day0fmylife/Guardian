# G-08 — isolation and operational runbook

Reviewed main `0e12301d4f37` and the ecosystem plan dated 2026-10-10.
G-07 PR #14 merged during implementation. G-08 was rebased onto the current
main `f9a89fe` before publication; its separate PR contains only G-08 changes.

## Gap assessment

Existing features reused: versioned service catalog, deterministic scope/device
grants, `services.read/manage` RBAC, hashed credentials, two-phase revocation,
WG key/config revision binding, default-drop lateral/public firewall, restart
reconciliation, bounded ACL leases, shared SQLite/PostgreSQL migrations and CI.
No replacement catalog, new tenant admin API, Redis dependency or other repo
change was needed.

Missing boundaries implemented:

- Site/group IDs previously matched globally without a durable owner. Migration
  009 backfills immutable tenant ownership; membership changes serialize and
  reject cross-owner references atomically. Legacy empty-tenant namespace stays
  supported. Device policies and bulk ACL snapshots validate owner consistency.
- Pool creation previously permitted overlap and allocation checked occupied
  addresses only within its pool. Creation now rejects any globally overlapping
  masked IPv4 CIDR under a database lock, and active/revoking leases have global
  uniqueness. Pool mutation and administrative audit are one transaction.
- The legacy suspension setter could rewrite terminal lifecycle states. It now
  rejects pending/revoking/revoked transitions; existing VPN resume already
  required suspended state. Final revoke requires re-enrollment, not resume.
- Existing operations notes implied unsupported in-place server-key/profile
  updates. The runbook describes the actual new-profile/re-enrollment cutover,
  protected backups, fenced restore, node failure, trust rotation, diagnostics,
  firewall and decommission/reinstatement.

See [isolation contract](tenant-isolation.md),
[operations runbook](operations-runbook.md), and updated service OpenAPI.
Global admin roles remain platform-wide; tenant membership controls device
service policy, not account visibility. Backends still authenticate their users.

## Validation (2026-10-10)

Passed:

- Full `go test -race ./...` with real PostgreSQL 16-alpine and SQLite,
  including the new restore test. This also runs existing role, credential,
  grant precedence, rotation, revocation, denial and compatibility scenarios.
- Additional race tests for simultaneous ownership and overlapping pool claims,
  global occupied-IP uniqueness and rollback after audit failure.
- Migration backfill/repeat plus rejection of ambiguous owners, overlapping
  pools and duplicate occupied addresses on both database dialects.
- API cross-owner 409, cross-device credential rejection, foreign policy secrecy,
  pool-overlap 409 and viewer/auditor/operator write rejection.
- `go vet ./...`, `CGO_ENABLED=0 go build ./cmd/...`, module verification/tidy.
- Frontend tests (6 tests, 24 assertions), frontend production build, Compose
  validation, shell syntax and `git diff --check`. Unchanged frontend >500 kB
  chunk advisory remains.

Restore is physical, not a SQL row-copy mock: SQLite `VACUUM INTO` creates a new
file; PostgreSQL `pg_dump`/`psql` restores the fixture schema into a new database.
The local PG leg used the explicitly selected disposable test container. It
preserves scoped grants, owners, policy revision and hashed authentication,
checks absence of both plaintext device credentials in the backup, denies
another tenant and exercises suspend/resume and completed revocation afterward.
PostgreSQL restore tests need pg_dump/psql or the documented test-container env,
and CREATEDB; they explicitly skip when external tools are unavailable.

Gateway acceptance completed with **ALL CHECKS PASSED** (158 PASS checks). Its fixture
now uses two tenants, A's group grant, cross-owner rejection and lateral checks
in both directions, then the existing grant/connection revoke, kernel expiry,
key rotation, API/reconciler restart after kernel peer loss and IP reuse scenarios. A grant transfer
prepares the pre-existing device-grant revocation scenario without changing
production behavior. No fixture credentials/private keys are included here.

The physical gateway run also passed suspend/reinstate, 7-second established TLS
connection denial, kernel lease expiry after controller crash, recovery after
kernel peer loss, stale-key denial, completed revoke and address reuse, repeated
ACL restart denial, trusted service TLS/upstream pin rejection, public ingress
and log-secret checks. Its temporary Compose stack was automatically removed.

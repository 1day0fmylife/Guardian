# G-04 implementation and verification

Baseline: main `26fc874`, inspected 2026-10-10. Open PR #10 implements G-03
identity/anti-spoofing and was inspected for overlapping scope.

Already implemented by G-01/G-02: immutable revisions for SunkarDAV,
Admiral device API and SunkarCWMP ACS; individual and scoped allow/deny grants;
services.read/services.manage RBAC; transactionally audited admin APIs;
deny-by-default effective policy; suspend/revoke revisions; migration 006;
SQLite/PostgreSQL matrix, negative API tests and legacy endpoint tests.
These are reused. No replacement tables or duplicate migration are added.

Delta: five-minute policy expiry, mandatory VPN marker, no-store responses,
revision-aware policy wakeups on the existing WebSocket, independent hint
coalescing, durable revision/credential checks at keepalive, OpenAPI additions,
refresh/retry contract and regression tests. No credentials, admin/NBI URLs,
CA secrets or arbitrary upstream metadata are exposed. Optional CA references
and pins are omitted because no device trust distribution policy exists yet.
Existing TLS policy continues to require certificate validation.

Compatibility: additive JSON fields and a new version-1 event. Existing
command, ready, keepalive and reauth events remain unchanged. Old clients must
ignore unknown event types; they cannot gain access because grants and gateway
enforcement remain authoritative. Migration 006's existing upgrade test covers
an old database with no grants and disabled services on both database dialects.

Deployment/hardware limits: client atomic application, lease expiry/backoff,
and actual VPN packet blocking need downstream ArlanPhone and installed G-03/
G-05 acceptance. Guardian tests establish its API/server behavior, not physical
or installed-stack acceptance. Poll fallback is specified for the downstream
client; it is not falsely claimed to have been implemented in another repo.

## Verification

Results are recorded after running checks on this branch.

- GUARDIAN_TEST_POSTGRES_URL=… go test ./...: PASS on SQLite and PostgreSQL 16.
- go test -race ./internal/httpapi: PASS, including real local WebSocket refresh,
  deny, idempotency, lifecycle, ordered revisions and revoked credentials.
- go vet ./... and CGO_ENABLED=0 go build ./cmd/guardian: PASS.
- go mod verify and go mod tidy -diff: PASS, no module changes.
- cd web && bun install && bun run build: PASS, 233 modules transformed.
  Generated lock/build files are excluded from this change.
- docker compose config --quiet: PASS.
- git diff --check and gofmt on changed Go files: PASS.

Local sandbox initially denied the WebSocket listener and Go cache writes;
checks were rerun with a temporary cache and authorized local networking.
The gateway acceptance script was not run for this API-only change.
- GUARDIAN_TEST_POSTGRES_URL=… go test -race ./...: PASS on SQLite and
  PostgreSQL 16; full store race matrix took 68 seconds. The final added
  lifecycle test was also rerun in the passing HTTP API race suite.

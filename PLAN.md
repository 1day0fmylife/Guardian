# Guardian implementation plan

## Goals

Guardian is a centralized WireGuard client management control plane for ArlanPhone and other managed devices. Phase 1 targets roughly 1,000 devices and manages clients only; direct lifecycle management of VPN servers is deferred.

## Architectural principles

1. Client WireGuard private keys are generated and retained on the managed device.
2. Guardian is the source of truth for device identity, public keys, address allocation, policy, desired state, commands, and audit history.
3. SQLite is supported for standalone/small deployments; PostgreSQL is the production database.
4. Redis is optional and never the authoritative data store.
5. Caddy terminates HTTP(S) and reverse-proxies the API and WebUI.
6. ArlanPhone privileged networking is performed through its existing netd boundary; the Guardian integration must not require a permanently privileged application process.
7. Public APIs are versioned below /api/v1.
8. Administrative mutations are authenticated, authorized by RBAC, and audited.

Status marks below were checked against `main` at `e5b5946` on 2026-09-28. `[x]` means implemented in the repository; `[ ]` means missing or only partly done, with the gap noted.

## Phase 0 — bootstrap

- [x] Establish repository and product scope.
- [x] Select Caddy as reverse proxy.
- [x] Go backend skeleton (`cmd/guardian`, `internal/*`).
- [x] WebUI skeleton (Bun/Vite/TypeScript/React, `web/`).
- [x] Caddy configuration (`deploy/Caddyfile`, `web/Caddyfile`).
- [x] Local compose stack (`compose.yaml`: Caddy, server, web, PostgreSQL, Redis).
- [x] Database configuration abstraction (`GUARDIAN_DATABASE_URL`, `sqlite://` or `postgres://`, `internal/store/store.go`).
- [x] Health/readiness endpoints (`GET /healthz`, `GET /readyz`).
- [x] CI checks (`.github/workflows/ci.yml`: Go test/vet/build, web build, Compose validation).

## Phase 1 — identity, RBAC, persistence

### Users and RBAC

Initial roles:

- superadmin — unrestricted platform administration.
- admin — permission-based platform device, enrollment, profile, address-pool and user administration; tenant-bound admin principals are not implemented.
- operator — operational device actions and configuration deployment.
- auditor — read-only access including audit logs.
- viewer — read-only operational views excluding sensitive administrative data.

Authorization must use permissions rather than hard-coded role checks. Initial permission namespace:

- devices.read / devices.create / devices.update / devices.delete
- devices.connect / devices.disconnect / devices.rotate_key / devices.reconfigure
- enrollment.read / enrollment.create / enrollment.revoke
- profiles.read / profiles.create / profiles.update / profiles.delete
- pools.read / pools.create / pools.update / pools.delete
- users.read / users.create / users.update / users.delete
- roles.read / roles.create / roles.update / roles.delete
- audit.read
- settings.read / settings.update

Status:

- [x] Permission-based RBAC with the five initial roles (`internal/rbac`); the namespace also adds `commands.read` and `commands.create`.
- [x] First-admin bootstrap, login/logout and server-side sessions (`/api/v1/auth/*`).
- [x] Users and roles administration API and pages (list, create, update, password reset).
- [ ] Delete endpoints: `users.delete` and `roles.delete` exist as permissions but no route uses them.

### Data model

Core entities:

- users
- roles
- permissions
- user_roles
- role_permissions
- devices
- device_identities
- wireguard_peers
- vpn_profiles
- address_pools
- address_leases
- enrollment_tokens
- device_commands
- device_telemetry
- audit_events

Device identity binds at least Guardian UUID plus ArlanPhone device UUID. Serial number and MAC address are captured as identity attributes; enrollment policy decides which attributes are mandatory.

Status:

- [x] All core entities exist in `internal/store/migrations` (001–005), plus `device_credentials` and `address_lease_history`.
- [x] SQLite and PostgreSQL share one migration set.
- [x] Core store, service catalog, migrations and persistence outage tests run on SQLite and real PostgreSQL when `GUARDIAN_TEST_POSTGRES_URL` is set; CI already provides PostgreSQL 16.

## Phase 2 — enrollment

Supported enrollment paths:

1. QR code shown in Guardian WebUI and consumed by ArlanPhone UI.
2. Provisioning URL.
3. Manual provisioning URL/token entry through the ArlanPhone WebUI.

Enrollment token requirements:

- random and high entropy;
- short-lived;
- single use by default;
- stored hashed, never stored as recoverable plaintext;
- bound to intended device attributes when those are known;
- all creation, use, expiration and revocation events audited.

Enrollment flow:

1. Administrator creates enrollment.
2. Guardian returns a provisioning URI suitable for QR representation.
3. ArlanPhone validates server identity and submits its device identity.
4. ArlanPhone generates a WireGuard keypair locally.
5. ArlanPhone sends only the public key to Guardian.
6. Guardian allocates an address and produces the non-secret desired WireGuard profile.
7. ArlanPhone delegates privileged interface/routing/DNS application to netd.
8. Agent reports resulting state and telemetry.

Status:

- [x] Enrollment tokens are high entropy, stored hashed, expiring, single use (`consumed_at`), revocable and optionally bound to device UUID, serial number and MAC.
- [x] Create, claim and revoke are audited; claim is `POST /api/v1/device/enroll`.
- [x] The device generates its WireGuard key and sends only the public key; Guardian allocates the address and returns the non-secret profile.
- [x] Device credentials are device-owned and rotatable (`POST /api/v1/device/credential/rotate`).
- [x] Local QR rendering of the provisioning URI, manual copy and clearance after expiry/use/revocation (G-06).

## Phase 3 — WireGuard client lifecycle

Functions:

- create/register peer;
- allocate address from pool;
- render/export configuration without client private key;
- suspend/resume;
- revoke;
- request key rotation;
- connect/disconnect;
- request reconfiguration;
- track desired state vs observed state.

Revocation removes the peer public key from active server configuration and invalidates any active management/enrollment credentials associated with the device.

Status:

- [x] Peer registration, address allocation with lease history, suspend/resume and revoke (`/api/v1/devices/{id}/*`).
- [x] Key rotation requested by the device (`/api/v1/device/wireguard/rotate-key`) with persisted rotation state.
- [x] Server-side peer reconciliation through `wgctrl` (`internal/wireguard`), tracking desired vs observed state.
- [x] Device credential revocation (`/api/v1/devices/{id}/credentials/revoke`).
- [ ] Administrative export of a device configuration (without private key); only the device itself can fetch it (`GET /api/v1/device/config`).
- [ ] Update/delete of VPN profiles and address pools: only list and create are routed.

## Phase 3b — service catalog and grants (Arlan ecosystem G-01)

Guardian brokers device access to SunkarDAV, Admiral and SunkarCWMP ACS. Design and API contract: `docs/service-catalog.md`, `docs/openapi/service-catalog.yaml`.

Status:

- [x] Versioned service definitions for `sunkardav`, `admiral-device` and `sunkarcwmp-acs`, seeded disabled (migration 006).
- [x] Tenant/site/group/device grants with deterministic precedence, deny-by-default and revocation history.
- [x] `services.read` / `services.manage` permissions; mutations audited in the same transaction.
- [x] Admin API and the non-secret `GET /api/v1/device/services` effective-policy endpoint.
- [x] Service gateway reference deployment (G-02): `deploy/service-gateway/`, `docs/service-gateway.md`; grants are projected to nftables sets by `guardian-gateway-acl`; acceptance test `scripts/verify.sh`.
- [x] Peer key/address ↔ device binding verified against the kernel peer table, anti-spoofing and L7 header/pinning policy (G-03), see `docs/service-gateway.md`.
- [x] Device refresh over the WebSocket wake channel (G-04), staged reconciliation SLOs (G-05), operator WebUI (G-06).

## Phase 4 — command and telemetry plane

Commands:

- connect
- disconnect
- rotate_key
- reconfigure

Each command has an idempotency key and lifecycle:

pending -> delivered -> acknowledged -> succeeded|failed|expired

Telemetry includes:

- online/offline;
- latest WireGuard handshake;
- assigned VPN address;
- current endpoint;
- rx/tx bytes;
- tunnel uptime;
- ArlanPhone version;
- agent version;
- WireGuard implementation/version when available;
- tunnel state;
- latency to configured gateway;
- normalized error state.

PostgreSQL stores durable/current and historical records according to retention policy. Redis may accelerate presence, command delivery and realtime WebUI events, but the system must function without Redis in single-instance mode.

Status:

- [x] Commands with a unique idempotency key and TTL, admin create/list, device poll and result reporting, and an outbound device WebSocket wake channel (`docs/device-websocket.md`).
- [x] Telemetry ingestion and latest-telemetry view with all fields listed above.
- [ ] Naming drifted from this plan: implemented command types are `connect`, `disconnect`, `apply-config` and `rotate-key`, and the lifecycle is `pending → delivered → running → succeeded|failed|expired`. Either the plan or the code should be aligned.
- [x] Opt-in bounded telemetry retention, dry-run maintenance command, atomic audit and latest-observation protection (`docs/telemetry-retention.md`).
- [ ] Redis: `GUARDIAN_REDIS_URL` is read and logged, but nothing uses it yet.

## Phase 5 — WebUI

Stack:

- Bun
- Vite
- TypeScript
- React
- TanStack Router
- TanStack Query
- TanStack Table
- Axios
- shadcn/ui
- Google Material Symbols
- Roboto

Design:

- responsive admin shell inspired by satnaing/shadcn-admin;
- centered/collapsible sidebar;
- command/search interface;
- light and dark themes;
- consistent table filters and detail drawers;
- no protocol secrets displayed unnecessarily.

Initial navigation:

- Dashboard
- Devices
- Enrollments
- VPN Profiles
- Address Pools
- Commands
- Users
- Roles
- Audit
- Settings

Status:

- [x] Stack as listed, except shadcn/ui: the UI uses its own CSS with `class-variance-authority`/`clsx`/`tailwind-merge` helpers, not shadcn components.
- [x] Sidebar with all initial navigation items, RBAC-aware; light and dark themes; Roboto and Material Symbols.
- [ ] Command/search interface.

## Phase 6 — deployment and observability

Caddy routes:

- /api/* -> guardian-server
- other paths -> guardian-web

Production deployment supports PostgreSQL and optional Redis. Standalone deployment supports SQLite and no Redis.

Observability:

- structured JSON logs;
- request IDs;
- Prometheus-compatible metrics;
- readiness/liveness endpoints;
- audit log separate from ordinary application diagnostics.

Status:

- [x] Caddy routes `/api/*`, `/healthz`, `/readyz` to the server and everything else to the web container.
- [x] Structured JSON logs, request IDs (`X-Request-ID`, stored on audit events), liveness/readiness endpoints, separate `audit_events` table.
- [x] Opt-in loopback Prometheus exporter with fixed labels, denial/reconciliation counters, DB and gateway probes (`deploy/monitoring/README.md`).

## Deferred

- OpenVPN client management and certificate lifecycle.
- Smallstep/Vault PKI provider integration.
- Guardian-managed WireGuard server/node lifecycle.
- mTLS device identity/enrollment.
- HA/multi-region control plane.

## G-04 — service discovery refresh (2026-10-10)

- [x] Reuse the G-01 versioned service catalog, per-device/scoped grants,
  services.read/services.manage API and migration 006.
- [x] Authenticated secret-free device policy includes mandatory VPN and expiry.
- [x] Existing WebSocket wakes policy refresh with monotonic coalesced revisions;
  durable revision polling covers other server instances.
- [x] API/OpenAPI and downstream polling/backoff contract documented in
  docs/device-websocket.md and docs/g-04-implementation.md.
- [ ] Installed device refresh/backoff and packet-path acceptance (G-03/G-05
  and downstream client); repository fixtures are not hardware evidence.

## G-05 — durable revocation and recovery (2026-10-10)

- [x] Reuse two-phase revoke and previous-key removal; reject overlapping
  rotation and stale lifecycle during credential/key renewal.
- [x] Kernel-expiring memberships and per-packet service checks bound denial
  for existing connections and controller crashes; no unrestricted recovery.
- [x] Migration 007 durably gates revoked-address release on applied ACL
  acknowledgement; allocator retains revoking addresses without blocking others.
- [x] Monotonic ACL revisions and consistent database snapshots; requeue
  non-finalized desired peers on reconciler startup after kernel state loss.
- [x] Document healthy/degraded propagation budgets, zero dual-key grace,
  coordinated namespace upgrade and systemd stop/restart behavior in
  docs/g-05-recovery.md.
- [ ] Physical-device/installed-stack acceptance remains separate from the
  disposable WireGuard/nftables/TLS fixture.

## G-06 — operator service access and enrollment (2026-10-10)

- [x] Reuse catalog/grants, RBAC, effective-policy API and migrations 006–007.
- [x] Device detail service decisions/revisions and individual Allow/Deny/Inherit.
- [x] Revision-checked catalog editing and permission-aware read-only controls.
- [x] Local one-time provisioning QR with manual copy and bounded display lifetime.
- [x] Paginated device/individual-grant audit timeline under audit.read.
- [x] SQLite/PostgreSQL, API negative/RBAC/compatibility and frontend tests;
  validation evidence in docs/g-06-implementation.md.
- [ ] Physical-camera and installed-stack acceptance; no hardware claim.

## G-07 — production persistence and observability (2026-10-10)

- [x] Existing PostgreSQL CI reused; older core-store tests extended to both database dialects.
- [x] Fixed-cardinality metrics and tested Prometheus alerts; exporter disabled by default and loopback-only.
- [x] Migration 008, bounded audited telemetry retention and preview/apply CLI.
- [x] Database connection loss, persisted restart and endpoint outage/recovery tests retain deny-by-default and revoked access.
- [x] PostgreSQL/SQLite tests, race detector, vet, command builds, frontend tests/build and monitoring validation passed locally.

Evidence and operational limits: `docs/g-07-implementation.md`.

## G-08 — tenant/network isolation and operations (2026-10-10)

- [x] Immutable site/group tenant ownership, compatible standalone namespace and atomic conflict rejection.
- [x] Globally non-overlapping tunnel pools and unique active/revoking IP addresses.
- [x] Migration 009 with legacy backfill and refusal of ambiguous/overlapping state.
- [x] Cross-tenant negative policy/API/ACL tests and real backup/restore into fresh SQLite/PostgreSQL environments.
- [x] Runbook for server keys, node recovery, backups, certificates, NAT/MTU/DNS, firewall and decommission/reinstatement.
- [x] Real gateway acceptance passed: cross-tenant/lateral/spoofing denial, suspend/resume, revocation, IP reuse, recovery and no secrets in logs.

Contract: `docs/tenant-isolation.md`; procedures: `docs/operations-runbook.md`;
verification evidence: `docs/g-08-implementation.md`.

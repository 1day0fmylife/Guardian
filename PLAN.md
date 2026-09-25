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

## Phase 0 — bootstrap

- [x] Establish repository and product scope.
- [x] Select Caddy as reverse proxy.
- [ ] Go backend skeleton.
- [ ] WebUI skeleton (Bun/Vite/TypeScript/React).
- [ ] Caddy configuration.
- [ ] Local compose stack.
- [ ] Database configuration abstraction.
- [ ] Health/readiness endpoints.
- [ ] CI checks.

## Phase 1 — identity, RBAC, persistence

### Users and RBAC

Initial roles:

- superadmin — unrestricted platform administration.
- admin — device, enrollment, profile, address-pool and user administration within assigned scope.
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

## Deferred

- OpenVPN client management and certificate lifecycle.
- Smallstep/Vault PKI provider integration.
- Guardian-managed WireGuard server/node lifecycle.
- mTLS device identity/enrollment.
- HA/multi-region control plane.

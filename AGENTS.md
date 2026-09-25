# AGENTS.md

## Project

Guardian is a centralized secure-access control plane focused initially on WireGuard client lifecycle management for ArlanPhone and other managed devices.

## Non-negotiable architecture

- Go backend.
- REST API below `/api/v1`.
- SQLite for standalone mode; PostgreSQL for production.
- Redis is optional and must not be the source of truth.
- Caddy is the reverse proxy / TLS edge.
- WebUI: Bun, Vite, TypeScript, React, TanStack Router, TanStack Query, TanStack Table, Axios, shadcn/ui, Material Symbols, Roboto.
- Full permission-based RBAC.
- Target initial scale: about 1,000 devices.
- Phase 1 supports WireGuard only.

## Security constraints

- Never generate or persist managed-device WireGuard private keys on Guardian Server.
- Private keys are generated on the managed device and stay there.
- Guardian stores WireGuard public keys only, plus configuration metadata.
- Enrollment tokens must be short-lived, single-use by default, cryptographically random and persisted only as hashes.
- Do not log credentials, bearer tokens, WireGuard private keys, session cookies or authorization headers.
- All privileged administrative mutations must produce audit events.
- Authorization must be permission-based, not scattered role-name checks.
- Sensitive compare operations should be constant-time where practical.
- Configuration exports from the server must not imply that a client private key can be recovered from Guardian.

## ArlanPhone integration

- Integrate through the existing Go core and privileged `netd` boundary.
- Guardian-related processes should not run permanently as root.
- WireGuard interface, route and DNS mutation is delegated to `netd`.
- Support enrollment through QR, provisioning URL and manual WebUI entry in the first integration phase.
- Bind enrollments/devices to ArlanPhone device UUID and optionally serial/MAC metadata according to policy.

## Backend conventions

- Keep domain logic independent of HTTP handlers and concrete persistence drivers.
- Define repository/service interfaces at domain/application boundaries.
- Avoid framework-heavy layering unless it provides real value.
- Prefer stdlib HTTP where practical; dependencies require justification.
- Every mutation endpoint should be designed for idempotency where retries are expected.
- Use UTC timestamps in API/storage.
- Expose stable machine-readable error codes in API errors.
- Add pagination/filtering/sorting to collection endpoints from the beginning.

## Persistence

- Schema must work on SQLite and PostgreSQL unless explicitly documented otherwise.
- PostgreSQL is the production reference implementation.
- Do not encode transient online presence solely in the relational database if Redis is enabled, but preserve enough durable state to recover after cache loss.
- Migrations are mandatory; never depend on implicit ORM auto-migration in production.

## WebUI conventions

- Follow the administrative information architecture described in PLAN.md.
- Support light and dark themes from the start.
- Use accessible shadcn/ui primitives and keyboard-friendly navigation.
- Use TanStack Query for server state and TanStack Router for routing.
- Do not mirror server entities into ad-hoc global stores without a concrete UI-state reason.
- Tables must support server-side pagination/filtering as datasets grow.
- Material Symbols are the icon source unless an exception is documented.

## Edge/deployment

- Caddy is the supported reverse proxy.
- `/api/*` routes to the backend; WebUI handles application routes.
- Containers/services must expose explicit health checks.
- Standalone mode should be runnable without PostgreSQL or Redis.
- Production compose/examples should use PostgreSQL and may enable Redis.

## Testing

At minimum add tests for:

- enrollment token hashing/expiry/single-use semantics;
- RBAC permission evaluation;
- WireGuard public-key validation;
- address allocation and uniqueness;
- revocation;
- command state transitions and idempotency;
- SQLite and PostgreSQL repository behavior where relevant;
- API authorization boundaries.

## Scope discipline

Do not add OpenVPN in Phase 1. Keep provider interfaces extensible enough for OpenVPN later, but do not distort the WireGuard implementation into premature abstraction.

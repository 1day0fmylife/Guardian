# Service catalog, grants and effective policy (G-01)

Guardian brokers device access to internal services. This document describes
the catalog, the grant model, the permission model and the API contract added
by G-01. The gateway/firewall enforcement of this policy is out of scope here
(G-02/G-03), as are device refresh over the WebSocket wake channel (G-04) and
the operator UI (G-06).

## Catalog

Three services are shipped in migration `006_service_catalog.sql`:

| id               | default DNS name (illustrative) | default state |
| ---------------- | ------------------------------- | ------------- |
| `sunkardav`      | `dav.internal`                  | disabled      |
| `admiral-device` | `fleet.internal`                | disabled      |
| `sunkarcwmp-acs` | `acs.internal`                  | disabled      |

New service identifiers cannot be created through the API; they are added by
migration. Each update of a service appends an immutable **revision**
(`service_definition_revisions`); the current revision is the one evaluated.

A revision holds: `display_name`, `internal_dns_name` (a bare DNS host name, no
scheme/port/path/IP-literal syntax), `protocol` (`https`, `http`, `tcp`),
`port`, `tls_policy` (`required`, `disabled`; `https` requires `required`,
`http` requires `disabled`), `allowed_scopes` and `enabled`.

`allowed_scopes` lists which grant scope types the service accepts. Grants for
other scope types are rejected on creation and ignored during evaluation, so
narrowing the list fails closed.

Updates use `expected_revision` for optimistic concurrency. Re-sending the
content that is already current is a successful no-op (`changed: false`), which
makes retries safe.

## Grants and precedence

A grant binds an `allow` or `deny` effect for one service to one scope:
`tenant`, `site`, `group` or a single `device` (device row id). Device
membership of tenant/site/groups is stored in `device_scope_memberships`
(one tenant, one site, many groups) and edited with
`PUT /api/v1/devices/{id}/scopes`.

Resolution is deterministic and deny-by-default:

1. The device must be `active` and not suspended, otherwise no access.
2. The service must be `enabled`.
3. Of the active grants that match the device and are allowed by
   `allowed_scopes`, the **most specific scope** wins:
   `device` > `group` > `site` > `tenant`.
4. Within that scope level a `deny` beats an `allow`; remaining ties resolve by
   grant id. The result never depends on row order.
5. No matching grant means no access.

Only one active grant exists per (service, scope type, scope id). Changing the
effect supersedes the old grant, which is kept as revoked history.

## Policy revision

`service_policy_state.revision` is a monotonically increasing counter. It is
advanced, inside the same transaction, by every service update, grant
set/revoke, scope membership change **and every device state change that
affects access** (enrollment activation, suspend, resume, revocation begin and
completion). A policy labelled with revision *N* is therefore never older than
*N*. The revision is read before the content, so a concurrent change can make
the content newer than the label but never older.

## Permissions

| permission        | allows                                                   |
| ----------------- | -------------------------------------------------------- |
| `services.read`   | catalog, revisions, grants, device scopes, admin policy  |
| `services.manage` | service updates, grant set/revoke, device scope changes  |

Default roles: `superadmin` and `admin` have both; `operator` and `auditor`
have `services.read`; `viewer` has neither. Existing installations receive
these through the idempotent RBAC seed at startup; custom roles are not
modified and therefore have no access until explicitly granted.

## Audit

Every mutation writes an audit event in the **same transaction** as the change:
`service.update`, `service_grant.set`, `service_grant.revoke`,
`device.scopes.update`. Events carry the actor user id, source IP, request id
and the resulting `policy_revision`. No credentials appear in details.

## Device effective policy

`GET /api/v1/device/services` with `Authorization: Guardian-Device <credential>`
returns the policy of the authenticated device only:

```json
{
  "device_id": "…",
  "access_state": "active",
  "revision": 17,
  "generated_at": "2026-10-10T12:00:00Z",
  "services": [
    {"id": "sunkardav", "display_name": "SunkarDAV", "host": "dav.internal",
     "port": 443, "protocol": "https", "tls_policy": "required", "revision": 3}
  ]
}
```

* Only services with an effective `allow` are listed; denied/ungranted/disabled
  services and the reason for a denial are not disclosed to the device.
* `access_state` is `active`, `pending`, `suspended`, `revoking` or `revoked`.
  Anything other than `active` yields an empty `services` list. A device whose
  credential is revoked receives `401`.
* The response contains no credentials, tokens, upstream URL paths or
  administrative/NBI endpoints, and `Cache-Control: no-store` is set.
* The endpoint is read-only and is not reachable with an administrator session.

Administrators get the same resolution with reasons and sources from
`GET /api/v1/devices/{id}/services` (`services.read`).

## Error codes

Stable codes returned in `{"error": {"code", "message"}}` by the new routes:
`service_not_found`, `device_not_found`, `grant_not_found`,
`invalid_service_definition`, `expected_revision_required`,
`service_revision_conflict`, `invalid_scope_type`, `invalid_scope_id`,
`invalid_effect`, `scope_not_allowed`, `invalid_sort`, `invalid_filter`,
`grant_state_conflict`, plus the existing `authentication_required`,
`invalid_session`, `permission_denied`, `invalid_request`.

The OpenAPI description is in [`openapi/service-catalog.yaml`](openapi/service-catalog.yaml).

## Operations notes

* Upgrade: apply migration 006 (automatic at startup). All services are
  seeded disabled with no grants, so upgrading grants nothing.
* Rollback: the migration only adds tables; older binaries ignore them. Device
  access is not enforced by the network until G-02/G-03 consume this policy.
* Tests: SQLite always; PostgreSQL when `GUARDIAN_TEST_POSTGRES_URL` is set
  (CI sets it). Each PostgreSQL test runs in its own schema.

# Profile rotation, trust bundle and re-enrollment after revocation

Server updates must never alienate an enrolled device. The cross-project
invariants (what survives updates, planned rotations, legitimate reasons to
re-provision a phone) are in Admiral `docs/adr/ADR-0001-server-updates-keep-phones.md`.
This page describes the Guardian side.

## Changing a VPN profile in place

`PUT /api/v1/vpn-profiles/{id}` (`profiles.update`) is a partial update:

```json
{
  "expected_revision": 3,
  "server_public_key": "<new gateway public key>",
  "endpoint": "192.0.2.10:51820",
  "allowed_ips": ["10.78.0.0/28"],
  "dns_servers": ["10.78.0.2"],
  "persistent_keepalive": 25,
  "rotation_grace_seconds": 604800
}
```

- `expected_revision` is required. A request identical to the stored profile
  is answered `200` with `changed: false` whatever revision it carries, so a
  retry after a lost response is safe. Any other stale request gets
  `409 revision_conflict`.
- `address_pool_id` is immutable (`409 profile_address_pool_immutable`).
- In one transaction Guardian stores the change, keeps the replaced key and
  endpoint as `previous_server_public_key` / `previous_endpoint` until
  `previous_valid_until` (default 7 days, at most 90), raises the
  `config_revision` of every peer of the profile (the gateway re-applies them),
  queues `apply-config` for every active device (idempotency key
  `profile:<id>:r<revision>:<peer>`, 24 h) and writes `vpn_profile.update` to
  the audit log. Connected devices are woken over the device WebSocket.
- Suspended devices are not commanded; they get the new values on resume.
- A name-only change raises the profile revision but not the devices'.

The device management channel (HTTPS to the device edge) does not run through
the tunnel, so a device whose tunnel no longer matches the gateway still
receives the new configuration. `GET /api/v1/device/me` returns
`config_revision`; an agent that missed the command (offline longer than its
TTL) compares it with its applied revision and fetches `/device/config`.

`GET /api/v1/vpn-profiles/{id}/rollout` (`profiles.read`) counts active devices
whose latest telemetry reports the current revision, lists the lagging ones and
sets `previous_key_retirable` once none is pending or the grace period is over.

WireGuard has one private key per interface, so after the gateway switches its
key a device has no tunnel until it applies the new configuration (seconds when
online). The `previous_*` fields allow a later dual-interface overlap without an
API change.

## Device trust bundle

`GET /api/v1/device/trust-bundle` (device credential) serves the PEM file named
by `GUARDIAN_DEVICE_TRUST_BUNDLE_FILE` (`/trust/bundle.pem` in
`deploy/service-gateway`): service CA anchors plus, during a CA rollover, the
cross-certificate of the next CA (its key certified by the current CA). Only CA
certificates are accepted; a malformed file yields `503
trust_bundle_unavailable`, never its content. Devices install a new anchor only
when its cross-certificate verifies against an anchor they already trust, so the
endpoint distributes trust but cannot create it.

## Re-enrollment after revocation

A device whose revocation has completed (`status = revoked`) can enroll again
with the same `device_uuid`:

| Device state | Enrollment | Result |
|---|---|---|
| `revoked` | bound to this `device_uuid`, same serial (if stored) | `201`, `reactivated: true` |
| `revoked` | unbound | `409 reenrollment_requires_bound_enrollment` |
| `revoked` | bound, other serial | `409 device_identity_mismatch` |
| `revoking` | any | `409 device_revocation_pending` |
| `suspended` | any | `409 device_suspended` (use resume) |

Reactivation keeps the device record (`device_id`, audit history, scope
memberships), reuses its peer row with a higher `config_revision`, allocates a
new address, issues a new device credential and records the old WireGuard keys
in `retired_wireguard_keys`, so they can never be enrolled again. The audit event
`enrollment.claim` carries `reactivated: true` and `previous_status`.

## Persistence

`deploy/service-gateway/scripts/deploy.sh` refuses a state directory on tmpfs
or ramfs (override `ARLAN_ALLOW_VOLATILE_STATE=1` for throwaway tests): the
WireGuard server key and the CA there must survive reboots.

Migration 012 only adds columns and a table, so the previous image keeps
working on the new schema.

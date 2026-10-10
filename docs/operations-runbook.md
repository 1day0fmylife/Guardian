# Guardian service gateway operations (G-08)

Use the existing [Compose deployment](service-gateway.md) or
[systemd units](../deploy/service-gateway/systemd/README.md),
[revocation/recovery contract](g-05-recovery.md),
[tenant isolation](tenant-isolation.md), and
[monitoring](../deploy/monitoring/README.md). This reference serves one database
and one gateway namespace. API stays unprivileged; only the local peer/ACL
processes need NET_ADMIN. Redis is optional and not restored as authority.

## Server keys and node replacement

The gateway server private key is a local root/service-owned 0600 file
(`state/wg/private.key` in Compose). Preserve it separately in encrypted backup;
Guardian stores only the public server/device keys. Never print `wg showconf`,
`wg show all dump`, private-key files or API/session credentials in diagnostics.
Use `wg show wg0 public-key`, `wg show wg0 latest-handshakes` and bounded metrics.
Logs shared outside operations must omit endpoint/device identities too.

For a failed node, fence the old node first: stop its service listener and WG
transport or block its network ingress. Restore the matching server key, PKI,
reviewed environment and DB into an isolated replacement. Initialize the
existing default-drop ruleset with empty ACL sets; requeue peers from durable
state via reconciler startup and start one ACL writer. Validate current key,
unique /32 bindings and required ACL revision before exposing ingress. Recreate
all Compose namespace-sharing consumers when replacing `wg-gateway`; a plain
restart does not move consumers into a new container's namespace.

Server-key rotation changes the peer identity known to clients. This release
has create/list VPN-profile APIs, no in-place profile-update or server-key
rotation orchestration API. Do not assume a profile refresh changes its key.
Prepare a maintenance window, protected new key file and a new VPN profile
with the new public key/endpoint. Revoke old enrollments/devices, wait for
revocation completion, and re-enroll clients against the new profile with
locally generated client private keys and reviewed memberships/grants. Test a
canary before reopening service ingress. A public-key change without coordinated
client provisioning causes handshake failure; do not keep the old gateway live
as a bypass. Replacing an intact failed node may reuse the protected original
server key instead, after fencing.

## Backup and restore into a new environment

Back up PostgreSQL, gateway key, environment and PKI as one recorded recovery
set. Stop application, reconciler, ACL and maintenance writers for a consistent
operational cutover snapshot. Keep the gateway listener fenced/default-drop.
Backups contain identity metadata, password/token hashes and certificate/server
private material; restrict storage and encrypt it. Hashes are not plaintext
credential exports, but the backup is still sensitive. No device private key
can be recovered from Guardian.

Use an existing protected libpq service/password file, rather than a connection
URL/password in shell history. Example PostgreSQL commands (the operator sets
PGSERVICE to the source or fresh destination service name):

```sh
umask 077
export PGSERVICE=guardian-backup
pg_dump --format=custom --no-owner --no-privileges --file=/secure/guardian.dump
export PGSERVICE=guardian-isolated-restore
pg_restore --exit-on-error --no-owner --no-privileges --dbname="service=$PGSERVICE" /secure/guardian.dump
```

Create an empty destination database first using the database operator's normal
procedure. Run the destination Guardian migration and RBAC seed before starting
controllers. For SQLite, stop writers and use SQLite's consistent backup API
(e.g. `sqlite3 /var/lib/guardian/guardian.db ".backup '/secure/guardian.db'"`);
do not copy only the main database while WAL writers are active. Install the
restored file in a 0700 directory with 0600 ownership for the Guardian service.

An older backup may omit later revocations. Reconcile all grants/revocations
against the incident/change record **while ingress remains fenced**, before
letting the ACL writer publish them. Never replay an old DB into a live gateway
with stale kernel sets. Set `GUARDIAN_SERVICE_ACL_REQUIRED=true` in reference
deployments and preserve its sticky DB requirement.

Restore verification: check catalog/policy revisions and owners; same-tenant
grants still apply; another tenant gets no endpoints; revoked tokens fail;
no raw credential/private key appears in API responses or diagnostics; active
leases are globally unique; old peers are absent; gateway starts default-drop.
Test readiness and monitoring, then a canary's trusted DNS/HTTPS path. Expose
only after review, and retire the source node to prevent dual writers.

Automated `TestIsolationBackupRestoreIntoNewEnvironment` restores SQLite via
`VACUUM INTO` and PostgreSQL via `pg_dump`/`psql` into a new database. The PG leg
requires `GUARDIAN_TEST_POSTGRES_URL` and installed pg_dump/psql (matching server),
or `GUARDIAN_TEST_POSTGRES_CONTAINER` pointing to a disposable test container;
the fixture role needs CREATEDB. It checks hashed authentication, plaintext
absence, preserved grants/owners and suspension/revocation after restore.
The test never infers a production database or regenerates client private keys.

## Revoke, suspend and reinstate

Use the authenticated management UI/API; do not log bearer headers or save API
responses containing newly issued enrollment credentials to incident tickets.

1. Temporary removal: `POST /api/v1/devices/{id}/suspend` (`devices.update`).
   Confirm suspended policy is empty, the disconnect revision is pending/applied
   and gateway memberships disappear. Its grant records stay intact.
2. Reinstate only after authorization review: `POST /api/v1/devices/{id}/resume`
   (`devices.update`). The existing key is requeued at a newer revision. Wait
   for matching applied/kernel peer and ACL revision; verify the permitted
   service and a forbidden service, and both directions of peer isolation.
3. Permanent decommission: `POST /api/v1/devices/{id}/revoke` (`devices.delete`).
   State is `revoking` until peer removal and required ACL acknowledgement;
   occupied address remains reserved. During draining, management credentials
   may still authenticate but service policy remains empty. Confirm final
   `revoked`, no current/previous peer keys, released lease and rejected token.
4. Revoke any outstanding enrollment and applicable explicit grants; review
   group/tenant grants rather than removing a shared grant for unrelated peers.
   Destroy device-local credentials/private key through the device's management
   process. No Guardian operation exports its private key.
5. `resume` cannot reinstate revoking/revoked devices. Re-enrollment with a new
   token/key is required; review old memberships/device overrides explicitly,
   since a surviving device UUID may retain its identity/history. Revoke stale
   overrides before issuing a replacement token if access should change.

The existing healthy deny budget is interval+5s (7s at shipped defaults), with
35s degraded kernel lease bound; see G-05 for assumptions. A failed nft apply is
an error, not evidence of successful denial. Do not release a revoking address
or fake applied revisions to clear a stuck queue. Re-run idempotent controllers
and repair the actual kernel/ACL error. Tests exercise suspend/resume,
revocation completion and terminal-state rejection on both DBs; gateway
acceptance exercises real peer deletion, lease reuse and restart recovery.

## Certificates, DNS, NAT and MTU

For service certificates, inspect expiry/issuer/SAN without exposing private
keys. Issue replacements for the configured internal names from the trusted CA,
install protected certificate/key files, validate Caddy config and reload/recreate
the proxy using the existing deployment procedure. With CA rotation, distribute
new trust to clients first, test a canary, then switch issuance and retire old
trust after all clients update. Upstream pins/trust files rotate separately:
update the reviewed upstream trust and certificate together. Never use `-k`,
HTTP downgrade, public DNS or WAN fallback to repair a production TLS failure.
(The gateway acceptance harness uses its own disposable test CA.)

| Symptom | Check | Safe correction |
| --- | --- | --- |
| No WG handshake | Correct public key/endpoint, UDP port ingress, clock and current server identity | Repair endpoint/transport; behind NAT use configured persistent keepalive; do not open service VIPs publicly |
| Handshake but DNS fails | Tunnel source /32, route to DNS VIP, dnsmasq and private records | Restore configured private DNS/routes; no public resolver fallback |
| DNS works, TLS fails | Trusted CA, hostname/SAN, expiry, time and upstream pin | Renew/reload verified cert/trust; maintain TLS validation |
| Large requests hang | Path MTU, encapsulation and filtered ICMP diagnostics | Measure tunnel MTU in a canary, reduce client/gateway consistently; no global routing/firewall bypass |
| Service denied despite handshake | Effective grant, lifecycle, policy revision, peer config/applied revisions, ACL sets and DB readiness | Repair reconciliation or scoped grant explicitly; never add an unrestricted nft accept rule |
| After DB/node outage | Readiness, DB metric, sticky ACL requirement, desired/applied state | Fence old node, recover one authoritative store, reinitialize empty sets and replay durable state |

## Host firewall and acceptance

Keep forwarding disabled/default-drop, expose only WG UDP plus the separately
protected Guardian enrollment/management HTTPS edges. Service VIP:443 and
VIP DNS are tunnel-only; upstream networks are private. A shared host requires
reviewing all other nft/iptables base chains, NAT rules and host services; do
not flush the host firewall or assume the reference table controls everything.
API must not gain NET_ADMIN, host network or a public metrics port.

Validate with `deploy/service-gateway/scripts/verify.sh` in a disposable Docker
environment supporting NET_ADMIN/WireGuard/nftables. It now provisions two
tenants, grants A through its owned group, rejects B's attempt to join that
group, denies B access to A's service, tests lateral traffic in both directions
and source spoofing, and retains prior public ingress/TLS/revoke/recovery tests.
This is destructive to its own temporary stack only; never run against a
production namespace. Inspect PASS/FAIL summaries without fixture credentials.

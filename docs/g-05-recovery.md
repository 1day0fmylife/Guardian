# G-05: bounded revocation and restart recovery

Baseline: main 46e962b (G-01 through G-04 merged), checked 2026-10-10.
Existing two-phase revocation, durable desired/config/applied revisions,
previous-key retention, kernel identity verification, default-drop rules,
atomic nft set replacement and G-04 refresh are reused.
Migrations 003/005/006 remain in use. Migration 007 adds only the durable ACL
applied revision, a sticky requirement flag and each revocation's policy
revision. It backfills already pending revocations and grants no access.

## Revocation sequence and propagation bounds

1. The database transaction sets the device to revoking/suspended, removes
   it from the service-policy snapshot, retains its address, and queues a
   disconnect. Management authentication remains usable only for draining.
2. The ACL controller removes its service memberships atomically. Every
   tunnel packet, including an already established TCP/TLS flow, must still
   match a service set. There is no conntrack shortcut for tunnel traffic.
3. The single ACL writer for this database/gateway acknowledges a revision
   only after the verified, complete nft transaction succeeds. Print-only dry
   runs and failed applies cannot acknowledge it.
4. The existing WG reconciler removes both current and previous keys for
   the exact desired revision. Only then does completion release the lease
   and invalidate credentials, and only after the deny revision has been
   acknowledged. Until then the allocator skips the revoking address and can
   enroll unrelated devices on other free addresses. This closes the gap where
   a reused address could inherit a stale grant. A stale completion cannot finalize a newer
   revision. A crash before completion leaves durable revoking state to retry.

With the shipped 2s ACL interval and 5s pass deadline, the healthy propagation
budget is **7s from committed revocation to denial of incoming service packets**.
Memberships have explicit **30s kernel leases**, renewed at most every 10s;
if the controller dies, cannot reach the database, cannot observe peers or
cannot apply nft, access expires without requiring a working userspace flush.
A pre-revocation snapshot may take up to 5s to finish applying, so the degraded
bound is **35s after commit**, subject to a functioning kernel/firewall.
An apply failure is reported as failure, never as successful fail-closed state.
No claim is made about undoing requests already processed by a backend.

CLI intervals must be positive and at most 5s, stale TTL at most 30s, and
resync at most 10s. Custom intervals alter the healthy budget to interval+5s.
The monotonic revision guard rejects older snapshots without a grace window,
including when a newer revision's apply previously failed. A new process
starts from the authoritative database; restoring an old DB backup is an
operational rollback, not a supported way to replay policies into a live
namespace. Recover it with an empty ACL and reviewed current revocations.

## Rotation and renewal

There is **no dual-key service-access grace**. After rotation commits, the
catalog revision advances and the binding names only the new key. The old key
is retained as removal metadata, not an authorized fallback. G-03 withholds the
grant while the kernel still has the old binding. The WG provider removes the
previous key and installs the new key in its existing configuration operation;
ACL recovery then honors only the new binding. Retrying the same key/revision
is idempotent, but a second different rotation is rejected until reconciliation
has cleared previous-key metadata. Enrollment and other devices cannot reuse
that previous key while removal is pending, preventing one device's removal
from deleting another device's newly applied peer. Failed apply/restart keeps
that metadata.
The device must durably retain its new private key before submitting rotation.

Credential renewal locks and checks the current lifecycle inside its database
transaction before the existing credential compare-and-swap. A principal
loaded before suspension/revocation cannot issue a replacement afterward.
Renewal does not modify service grants, policy revision or allowed endpoints.

## Recovery and upgrade

At WG-enabled Guardian/reconciler startup, non-finalized peers are requeued
from durable desired state, even if the prior instance recorded them applied.
This reconstructs an emptied kernel interface. Revoking peers retain removal
state; finalized revoked devices are never requeued. Startup, retry and ruleset
reload do not enable unrestricted forwarding. Policy and ACL reads now use one
serializable, read-only database snapshot on SQLite and PostgreSQL.

The reference Compose/systemd environments set GUARDIAN_SERVICE_ACL_REQUIRED=true.
The requirement persists in the database: a process missing the flag cannot
bypass it on restart. Standalone WireGuard deployments that never enable the
service gateway retain their prior two-phase behavior. The ACL database role
needs UPDATE on service_acl_state in addition to policy reads. Run one ACL
writer for the one gateway namespace served by this reference database.

Install migration 007, the new nft template and the binaries together. Older sets without
`flags timeout` cannot accept leased elements; failed application remains an
error. Do not roll back to permanent memberships to repair that error.
For Compose, from the repository root with STATE_DIR set to the existing state:

```bash
docker compose --env-file "$STATE_DIR/.env" -f deploy/service-gateway/compose.yaml \
  stop guardian-api guardian-acl guardian-reconciler gateway-proxy gateway-dns
docker compose --env-file "$STATE_DIR/.env" -f deploy/service-gateway/compose.yaml \
  up -d --build --force-recreate --wait wg-gateway guardian-reconciler \
  guardian-api guardian-acl gateway-proxy gateway-dns
```

Recreate all namespace-sharing consumers when recreating wg-gateway; simply
restarting the namespace owner does not move old containers to its new
namespace. The gateway initializer atomically installs the default-drop
ruleset with empty service sets. Wait for peer/ACL recovery before probing
services. Rollback must retain the leased/default-drop firewall until reviewed.

For systemd, stop guardian-api and the gateway network before updating all
binaries/units/template. Daemon-reload, then start guardian-api and
guardian-gateway-network.service. PartOf propagates restart to its consumers.
ExecStopPost reloads the empty default-drop ruleset rather than deleting the
firewall, so stopping the gateway cannot expose its local VIP listeners.
If that reload fails, existing memberships still expire in the kernel.

## Verification

Repository and disposable-stack results:
The disposable topology uses real Linux WireGuard/nftables and TLS with stub
backends; it is not physical ArlanPhone or installed production evidence.

- GUARDIAN_TEST_POSTGRES_URL=… go test -race ./...: PASS, SQLite and
  PostgreSQL 16, including migration 007 upgrade with pending revoke, durable
  ACK/stale/future ACK, held-address allocation, credential renewal, RBAC,
  legacy enrollment and previous-key reservation. Store matrix: 184 seconds.
- go vet ./...: PASS.
- CGO_ENABLED=0 go build ./cmd/guardian and ./cmd/guardian-gateway-acl: PASS
  (outputs kept outside source).
- go mod verify and go mod tidy -diff: PASS, no module changes.
- cd web && bun run build: PASS, 233 modules transformed.
- docker compose config --quiet, bash -n on acceptance scripts, gofmt and
  git diff --check: PASS.
- Compiled ACL CLI dry-run smoke against a fully migrated temporary SQLite
  fixture: source revision 17, acknowledged revision 3; dry-run/once/skip-peer-
  verification left acknowledged revision at 3, as required. Invalid interval,
  resync and non-dry-run skip-peer-verification configurations were rejected.

Initial PostgreSQL checks ran before database readiness and were repeated
successfully. A test expectation was corrected for enrollment advancing policy
revision. The first disposable network run passed 122 checks before the ACK
stage was added; a subsequent rotation run caught a fixture CA mismatch
(edge Caddy CA differs from service CA), which was corrected without disabling
TLS verification. The final run with migration 007 and the ACK gate enabled
completed successfully: 147 PASS checks, exit 0. It covered established-flow
revocation, controller crash/lease expiry, lost kernel state, staged key
rotation, restart during revoke, address reuse without inherited grants,
suspension and secret-free container logs.

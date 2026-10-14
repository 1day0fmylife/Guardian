# Managed IPv4 CWMP Connection Request

The default gateway/Core profile keeps Connection Request disabled. This optional
capability permits one ACS backend to reach port 7547 on currently granted,
cryptographically bound WireGuard device addresses. The phone listener stays in
its CWMP namespace at `169.254.177.2:7547`; no host/WAN listener, peer forwarding,
NBI access or device credential is added to Guardian policy.

## Contract and authorization

Migration 010 adds `connection_request` to immutable service revisions, disabled
for all existing rows. Only the `sunkarcwmp-acs` HTTPS/TLS catalog service accepts:

```json
{"connection_request":{"source_address":"10.78.0.12","port":7547}}
```

`source_address` is the gateway's ACS VIP (`VIP_ACS`), a single canonical private
IPv4 address. Port 7547 is fixed. The existing `services.manage` permission,
expected revision, transaction, policy revision and audit event apply. Device
responses include the optional object only while the service/device grant is
allowed. Other services, public/mapped/prefix sources and arbitrary ports are
rejected. In the administrative PUT API, omission preserves the existing object
for older UI/clients; explicit JSON null removes it. Store callers use nil to
remove the object. Removal retains the ordinary ACS service grant.

The reverse gateway set contains only peers that both have the ACS grant and
match the configured callback source. Existing kernel key/address/revision
verification runs before projection. The CR set is renewed and flushed in the
same nft transaction as ordinary grants; membership expires after 30s even if
the projector dies. Revocation rechecks membership on established replies.
Core/netd adds an independent lease of at most 20s (normally 15s), source pinned
to the currently resolved ACS endpoint, so an unavailable Core cannot leave
callback access open.

## Rollout order

1. Build/flash the updated ArlanPhone Core/netd/provider. Keep catalog callback
   metadata absent until every relevant managed client supports it: old clients
   reject unknown optional metadata when it is present.
2. Install the updated Guardian API/migration and gateway binary/templates.
   Existing gateway behavior remains unchanged with the CR settings empty.
3. Explicitly opt into the routed gateway profile. Set all of:
   `CWMP_CR_SOURCE=10.78.0.12` (equal to `VIP_ACS`),
   `CWMP_CR_BACKEND_ADDRESS=<one private ACS backend IPv4 address>`, and
   `CWMP_CR_BACKEND_INTERFACE=<actual backend-facing interface>`.
   For Docker set `CWMP_CR_IP_FORWARD=1`; the runtime configures forwarding
   before mounting `/proc/sys` read-only. Gateway interfaces are pinned:
   public `eth0`, upstream `eth1`, control `eth2`. Set the backend interface
   according to the actual backend route. The reference deployment requires Docker Engine >= 28.1 and Compose >= 2.36
   for `interface_name`; `deploy.sh` checks the Engine before starting containers.
   Validate Compose parsing using `docker compose config --quiet`.
   Gateway acceptance CI installs Engine 28.1.1 explicitly.
   Compose passes the source to `guardian-gateway-acl -cwmp-cr-source`.
   For systemd, the network unit reads `gateway.env`; the projector reads
   `guardian.env`, which must contain the same `CWMP_CR_SOURCE`.
4. Provide a return route from the ACS backend to the device tunnel prefix via
   the gateway's backend address. Any host/transit firewall must permit only
   this backend-to-device TCP/7547 path and its established replies. The gateway
   profile retains default-drop forwarding, checks the expiring device set,
   and SNATs accepted requests to the ACS VIP. IPv6 CR is not implemented here.
5. Update the ACS catalog entry using its current expected revision and the
   object above; keep the ordinary device-scoped ACS grant. Obtain separate CR
   credentials from ACS for that device and deliver them via the phone's existing
   typed Core provisioning boundary, preserving all existing CWMP configuration.
   Use the issued realm. Core derives listen/advertised URL; a supplied different
   target is refused. Refresh the service policy and explicitly apply the config.
6. Approve the exact advertised `http://<assigned WG IPv4>:7547/cwmp-connection`
   in ACS, with a narrow CR CIDR/port policy. Queue a GPV, issue the authenticated
   CR and verify Inform `6 CONNECTION REQUEST`, the completed task and Admiral
   references. Never treat periodic Inform as evidence of a successful CR.

No active pilot gateway/device policy is changed by merging this code. The
physical `101.16.0.1` check and deployment gate remain open until updated firmware
is flashed and the complete installed route/credential/deny matrix is measured.

## Validation

Tests cover legacy/default nil policy, explicit opt-in, idempotency, immutable
revision/atomic audit, grant/removal, API omission/null behavior, unsafe inputs,
source mismatch and stale-source flushing on SQLite and PostgreSQL. The isolated
packet fixture loads the actual optional nft template and proves empty/granted/
revoked membership, exact backend/interface, ACS-VIP SNAT, wrong-port and
peer-to-backend denial. It uses disposable veth namespaces; existing Guardian
binding tests establish the separate WireGuard ownership boundary.

```sh
GOCACHE=/tmp/guardian-cr-go-cache go test -c -o /tmp/guardian-cr-gateway.test ./internal/gatewayacl
GUARDIAN_CR_PROFILE_TEMPLATE="$PWD/deploy/service-gateway/cwmp-cr.nft.tmpl" \
GUARDIAN_CR_PARENT_NETNS="$(readlink /proc/self/ns/net)" \
unshare -Urn /tmp/guardian-cr-gateway.test -test.run '^TestConnectionRequestGatewayPackets$' -test.v
```

Run database/race regression tests with `GUARDIAN_TEST_POSTGRES_URL` pointing to
an exclusively disposable database. No physical hardware PASS is claimed.

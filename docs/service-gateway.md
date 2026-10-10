# Service gateway reference deployment (G-02)

This is the production reference for giving managed devices access to
SunkarDAV, Admiral (device API) and SunkarCWMP ACS **only through** a
WireGuard tunnel terminated by Guardian. It consumes the service catalog and
grants from [`service-catalog.md`](service-catalog.md) (G-01).

Files live in [`deploy/service-gateway/`](../deploy/service-gateway):
`compose.yaml` (Docker), `systemd/` (bare metal), `scripts/deploy.sh`
(clean-environment deployment) and `scripts/verify.sh` (acceptance test).

> The root `compose.yaml` and `deploy/Caddyfile` (plain HTTP on `:80`) are a
> **development stack only** and must not be used in production.

## Topology

```
                         public network                      tunnel (wg0)
 device ──tcp/443──▶ edge (Caddy) ──▶ guardian-api          device ──udp/51820──▶ wg-gateway
 device ──udp/51820───────────────────────────────────────────────────────────────▶   │ (nftables)
 admin  ──tcp/8443──▶ edge (Caddy, management listener)                               ├─ gateway-dns   (VIP_DNS:53)
                                                                                      ├─ gateway-proxy (VIP_*:443) ─▶ upstream net ─▶ SunkarDAV / Admiral / ACS
                                                                                      ├─ guardian-reconciler (wg0 peers)
                                                                                      └─ guardian-acl        (nft sets ← Guardian grants)
```

| Component | Privilege | Notes |
| --- | --- | --- |
| `guardian-api` | none (`cap_drop: ALL`, read-only rootfs, no host network) | control-plane only, `GUARDIAN_WIREGUARD_INTERFACE` empty |
| `edge` | `NET_BIND_SERVICE` | Separate listeners: `:443` exposes only `/api/v1/device/*` and `/healthz` (enrollment/device channel); `:8443` serves WebUI + admin API and should be published on a management address |
| `wg-gateway` | `NET_ADMIN`, no Guardian code | WireGuard interface, service VIPs, nftables; holds the server key as a file secret |
| `gateway-proxy` | `NET_BIND_SERVICE` | Caddy bound **only** to the service VIPs, TLS from the private CA |
| `gateway-dns` | `NET_BIND_SERVICE`, `SETUID/SETGID` | dnsmasq, authoritative for the three names, no recursion |
| `guardian-reconciler` | `NET_ADMIN` | the existing peer reconciler (`wgctrl`), serving only loopback |
| `guardian-acl` | `NET_ADMIN` | `guardian-gateway-acl`, projects grants to nftables sets |

The API process never holds network privileges: peer changes and firewall
sets are applied by separate containers/units that share the gateway network
namespace and read the same database.

## Addressing and DNS

* `TUNNEL_CIDR` (default `10.77.0.0/24`): the Guardian address pool; the
  gateway is `WG_ADDRESS`.
* `VIP_NET` (default `10.78.0.0/28`): service addresses on the gateway's
  loopback, outside the pool. Clients route only this prefix through the
  tunnel (set it as the VPN profile `allowed_ips`; set `VIP_DNS` as the
  profile `dns_servers`). One VIP per service lets the firewall authorize
  per service.
* Names (`dav.internal`, `fleet.internal`, `acs.internal`) are illustrative.
  They must equal each service's `internal_dns_name` in the Guardian catalog,
  because that is what devices receive from the policy API.

## What is enforced

1. **Unprovisioned peer** – no WireGuard peer entry, no handshake, no packets.
2. **Provisioned peer without a grant** – tunnel up; DNS answers; every
   service VIP drops its packets (peer address not in the service set).
3. **Granted peer** – reaches exactly the VIPs of services the G-01 policy
   resolves to *allow*; everything else is dropped.
4. **Suspended / revoking / revoked device** – excluded from the policy
   snapshot within one sync interval (default 2 s), independently of when the
   WireGuard peer itself is removed.
5. **No forwarding** – `forward` policy is drop and `ip_forward=0`; peers
   cannot reach the control or upstream networks nor each other.
6. **Public side** – only `udp/<WG_PORT>` is accepted from non-tunnel
   interfaces; the service listeners are not bound there at all.
7. **Backends** – live on `internal` Docker networks without published ports.
   On bare metal, restrict backend listeners to the gateway address.

The nftables ruleset is static (`nftables.conf.tmpl`); `guardian-acl` only
replaces the contents of the `svc_*_v4` sets, atomically (`nft -f -`). If the
policy cannot be read for longer than `-stale-ttl` (default 30 s) all sets
are flushed (deny). Each membership also expires in the kernel after 30 s,
including a controller crash. Sets are renewed every `-resync` (default 10 s,
maximum 10 s) so a reloaded ruleset is repopulated. Tunnel packets recheck the
service grant on every packet, including established connections.

## Deploy

```bash
deploy/service-gateway/scripts/deploy.sh [state-dir]
```

The script creates `state/.env` (random database password), a WireGuard
server key, a private CA and the gateway certificate, then starts the stack
and prints the server public key plus the profile values. Afterwards:

1. Open `https://<GUARDIAN_MGMT_HOST>:8443`, bootstrap the first admin.
2. Create the address pool (`TUNNEL_CIDR`) and a VPN profile with
   `server_public_key`, `endpoint=<public host>:<WG_PORT>`,
   `allowed_ips=<VIP_NET>`, `dns_servers=<VIP_DNS>`.
3. Enable the services in the catalog and grant them to devices (API in
   `service-catalog.md`).
4. Distribute `state/pki/ca.pem` to devices as the trust anchor for the
   service names.

For production replace the generated CA/certificate with your own
(`gateway.crt`, `gateway.key`, `upstream-ca.pem`), set `EDGE_TLS` to an ACME
address or certificate paths, and point `UPSTREAM_*` at the real backends
(HTTPS only; `upstream-ca.pem` is the trust anchor).

## Verify

```bash
deploy/service-gateway/scripts/verify.sh
```

Builds a throw-away stack with stub upstreams in its own Compose project and
state directory, provisions two devices with different grants through the
real API/enrollment, and runs real WireGuard clients in containers:

* public-side TCP/UDP probes fail; internal hosts are not resolvable
* gateway: `ip_forward=0`, input/forward policy drop, API without capabilities
* device A reaches only SunkarDAV, device B only Admiral and ACS (trusted TLS
  via the private CA); DNS resolves the VIPs; plain HTTP, the gateway tunnel
  address and another peer's address are unreachable
* a random (unprovisioned) key gets no handshake
* after suspend and after revoke the device reaches nothing
* a restart of `guardian-acl` does not reopen access

Needs Docker with Compose ≥ 2.24 and permission to run containers with
`NET_ADMIN`. It needs no host WireGuard tools. It does not touch the
repository's development stack.

## Operations

* **Health**: every service has a container healthcheck (`wg show` +
  `nft list table`, Caddy `/healthz` on loopback, Guardian `healthcheck`).
  `docker compose ps` shows `healthy` only when the data path is configured.
* **Backup**: back up PostgreSQL (Guardian is the source of truth for peers,
  grants and audit), `state/wg/private.key` (server key) and `state/pki`.
  Peers and ACL sets are rebuilt from the database on start.
* **Restart behavior**: a restart of `wg-gateway` recreates the interface and
  an empty (deny) ACL; the reconciler re-adds peers and `guardian-acl`
  repopulates the sets within `-resync`.
* **Key rotation**: replacing `state/wg/private.key` changes the server public
  key; update the VPN profile and let devices refresh their configuration.

## Identity and trust boundaries (G-03)

**What identifies a device at the gateway.** The WireGuard peer, i.e. its
public key, authenticated by the Noise handshake. The tunnel source address
is only a *derived* identity, and only because WireGuard drops any packet
whose source is outside the allowed-ips of the peer that authenticated it.
Guardian attests one binding per active device:

```
device id (immutable) <-> WireGuard public key <-> one tunnel /32 <-> config revision
```

`guardian-gateway-acl` honors a grant for an address **only** when the live
kernel peer table (`wgctrl`) agrees with that binding:

| Kernel state | Result |
| --- | --- |
| peer with the attested key, allowed-ips exactly the attested `/32`, no other peer routes it | grant applied |
| attested key absent (removed peer, disconnected, not yet reconciled, rotated away) | denied: `peer_not_in_interface` |
| key present but allowed-ips differ (other address, extra prefixes, a whole subnet, none) | denied: `allowed_ips_mismatch` |
| another peer also routes that address | denied: `address_claimed_by_other_peer` |
| two active Guardian peers claim the same address (e.g. overlapping pools) | both denied (`AddressConflicts`) |
| key unknown to Guardian | never receives a grant (reported as unexpected) |

Consequences:

* **Forged source address** – a peer cannot present another peer's address:
  the kernel drops it. The gateway also drops tunnel packets sourced from the
  gateway's own address and anything outside `TUNNEL_CIDR`.
* **Reused address** – when Guardian re-leases an address, the old key holder
  does not inherit the new device's grants (the kernel still maps the address
  to the old key, so the binding does not verify), and the new device is
  honored only once its own peer owns the address.
* **Key rotation** – the attested key changes with the revision immediately;
  until the reconciler swaps the kernel peer the device is denied service
  access (fail closed, one reconcile interval).
* **Removed peer** – access disappears when the peer leaves the interface,
  even if the database still lists the device as active.
* **Lateral movement** – nothing is forwarded; allowed-ips wider than a
  single host route disable the peer's grants.
* If the kernel peer table cannot be read, the ACL behaves like a policy
  outage: last verified state for at most `-stale-ttl`, then deny.

**What the gateway tells backends (L7).** TLS is terminated at the gateway
(per-service VIP, private CA). Toward DAV/ACS/Admiral:

* `X-Forwarded-For` is **set** (not appended) to the peer's tunnel address,
  taken from the transport connection. It may be used by a backend as
  "WireGuard-authenticated source" and mapped back to a device through
  Guardian; it is not a user or device credential.
* `X-Forwarded-Proto: https` is set. Everything else a client can send that
  looks like identity or forwarding is removed: `Forwarded`,
  `X-Forwarded-Host/Port/Server`, `X-Original-Forwarded-For`, `X-Real-IP`,
  `True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `Via`,
  `X-Remote-User`, `Remote-User`, `X-Forwarded-User`,
  `X-Authenticated-User`, `X-Auth-Request-User` and `X-Guardian-*`.
* `Authorization` is passed through unchanged: SunkarDAV users, ACS per-device
  Digest credentials and Admiral device credentials keep being authenticated
  by their owners. The gateway adds **no** per-request device authentication
  of its own; headers received from a client are never identity.
* Guardian's own API ignores every forwarding header: the audit source is the
  transport peer and device identity comes only from the
  `Guardian-Device` credential.
* Upstream TLS is verified per service against a trust file
  (`UPSTREAM_*_TRUST`, a CA bundle or the backend's leaf certificate, i.e. a
  pin) and a fixed server name (`UPSTREAM_*_SNI`). A certificate that the
  same CA signed but that is not the pinned leaf is rejected (HTTP 502).

**Scope changes** are applied by replacing the contents of all service sets
in a single `nft -f -` transaction; an unchanged service of an unchanged
device is never interrupted. **Logging**: the ACL logs device ids, reasons
and counts only; keys, addresses, tokens and database URLs are not logged.

## Scope boundaries

Implemented here: the reference deployment and the grant→firewall projection.
Not implemented here and tracked separately:

* Device-side application/retry/backoff of G-04 policy; the Guardian refresh
  channel and policy API are implemented.
* Physical-device acceptance of G-05; the server and disposable gateway
  verification are documented in `docs/g-05-recovery.md`.
* IPv6 tunnel addresses are not projected into sets (never allowed).
* Per-request device authentication at the gateway (e.g. signed identity
  assertions to backends) is intentionally absent; add it only for endpoints
  that need it and are reached through this gateway.

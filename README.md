# Guardian

Guardian is a centralized secure-access and VPN client management platform for ArlanPhone and other managed devices.

## Phase 1 scope

- WireGuard client lifecycle management
- Device enrollment via QR code, provisioning URL, and manual WebUI setup
- Device identity binding (device UUID / serial / MAC metadata)
- Client-side WireGuard private-key generation; private keys never leave the managed device
- Configuration generation and export
- Connect / disconnect / rotate-key / reconfigure commands
- Revocation and temporary suspension
- Connection telemetry: online state, latest handshake, endpoint, RX/TX, uptime, latency, errors
- REST API with OpenAPI
- Full RBAC and audit log
- SQLite for standalone deployments; PostgreSQL for production
- Optional Redis for ephemeral state, distributed coordination, rate limiting, and realtime delivery
- React administration UI
- Caddy reverse proxy

## Target scale

Initial design target: approximately 1,000 managed devices.

## Stack

### Backend

- Go 1.24
- REST/JSON API under `/api/v1`
- SQLite / PostgreSQL behind a shared persistence layer
- Redis optional
- `wgctrl` for the optional local WireGuard provider

### Web UI

- Bun
- Vite
- TypeScript
- React
- TanStack Router
- TanStack Query
- TanStack Table
- Axios
- shadcn/ui
- Material Symbols
- Roboto
- Light and dark themes
- Administration layout inspired by `satnaing/shadcn-admin`

### Edge

- Caddy

## Security model

WireGuard private keys are generated on the managed device. Guardian stores only public keys and management metadata. Device enrollment credentials are short-lived. Permanent device credentials and administrator sessions are stored hash-only. Administrative actions are RBAC-protected and audited.

WireGuard peer changes are revisioned. Key rotation preserves the previous public key until the exact desired revision has been applied, so the old peer can be removed safely. Revocation is two-phase: the peer is removed first, and only after successful reconciliation are the address lease released and device credentials revoked.

## Local WireGuard provider

Guardian can operate either as a control plane only or reconcile peers directly to an existing local WireGuard interface.

Control-plane-only mode is the default:

```env
GUARDIAN_WIREGUARD_INTERFACE=
```

To enable the local provider, create and configure the server WireGuard interface outside Guardian, including its private key and listen port, then set for example:

```env
GUARDIAN_WIREGUARD_INTERFACE=wg0
GUARDIAN_WIREGUARD_RECONCILE_INTERVAL=5s
GUARDIAN_WIREGUARD_RECONCILE_BATCH=100
```

Guardian changes only peer entries. It does not create, read, rotate, replace, or persist the server private key.

The Guardian process must have access to the WireGuard interface and sufficient operating-system privileges for the platform's WireGuard control API. On Linux this normally means running in the relevant network namespace with the required network-administration capability. Do not grant those privileges when `GUARDIAN_WIREGUARD_INTERFACE` is empty.

The local provider is intended for standalone/single-node deployments and development. The production multi-node design keeps the central API unprivileged and moves `wgctrl` access into dedicated Guardian node agents authenticated to the control plane.

## Integration with ArlanPhone

Guardian integrates with the existing ArlanPhone Go core and privileged `netd` network layer. The Guardian agent must not run permanently as root; privileged WireGuard, routing, and DNS operations are delegated to `netd`.

The expected device flow is:

1. ArlanPhone receives a short-lived enrollment token.
2. The device generates its WireGuard private/public key pair locally.
3. Only the public key and device identity are sent to Guardian.
4. Guardian allocates an address and returns the managed configuration plus a one-time permanent device credential.
5. The ArlanPhone agent polls/receives commands, applies privileged changes through `netd`, and submits telemetry/results.
6. Key rotation generates a new private key locally and sends only the new public key to Guardian.

## CI

The repository keeps Go dependency metadata locked. CI runs:

```text
go mod verify
go mod tidy -diff
go test ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/guardian
```

The WebUI is built with Bun and Docker Compose is validated independently.

## Status

The Phase 1 control-plane foundation, enrollment/IPAM, device management channel, revision-safe WireGuard lifecycle, reconciliation boundary, and optional local `wgctrl` provider are implemented in the bootstrap branch. The next major integration target is the Guardian agent in ArlanPhone and the production node-agent boundary for remote WireGuard gateways.

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

## Planned stack

### Backend

- Go
- REST/JSON API under `/api/v1`
- SQLite / PostgreSQL behind a shared persistence layer
- Redis optional

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

WireGuard private keys are generated on the managed device. Guardian stores only public keys and management metadata. Device enrollment credentials are short-lived. Administrative actions are RBAC-protected and audited.

## Integration with ArlanPhone

Guardian will integrate with the existing ArlanPhone Go core and privileged `netd` network layer. The Guardian agent must not run permanently as root; privileged WireGuard, routing, and DNS operations are delegated to `netd`.

## Status

Initial project bootstrap is in progress.

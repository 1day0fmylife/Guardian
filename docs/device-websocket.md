# Device WebSocket wake channel

Guardian exposes an optional low-latency wake channel for managed devices at:

```text
GET /api/v1/device/ws
Authorization: Guardian-Device <permanent-device-credential>
```

Production deployments use `wss://` through the normal Guardian HTTPS endpoint. Caddy's `reverse_proxy` handles WebSocket upgrade automatically; no separate listener or port is required.

## Purpose

The WebSocket is deliberately **not** a second command transport. Durable command state remains in `device_commands` and devices continue to fetch commands, submit acknowledgements/results, configuration and telemetry through the authenticated HTTP API.

The socket only carries small JSON wake-up signals:

```json
{"type":"ready","version":1}
{"type":"commands_available"}
{"type":"keepalive"}
{"type":"reauth_required"}
```

No command payload, VPN configuration, enrollment token, permanent device credential, WireGuard private key or preshared key is sent in WebSocket frames.

## Delivery semantics

`commands_available` is edge-triggered. Multiple wake-ups may be coalesced because one HTTP command poll is sufficient to discover all currently deliverable durable commands.

Immediately after a successful WebSocket connection Guardian sends `ready` and then `commands_available`. This closes the race where a command was committed immediately before the socket connected or reconnected.

Admin operations that successfully create a command or change device lifecycle state publish a wake-up after the HTTP mutation returns a 2xx status. Failed admin mutations do not publish a wake-up.

Credential revocation is different: `reauth_required` uses a dedicated priority channel and cannot be dropped behind ordinary wake-ups. Guardian attempts to send it and then closes the socket. A revoked credential cannot establish a new connection.

## Suspended and revoking devices

The WebSocket uses the same permanent device credential as the existing management API, but it intentionally does not require the device to be active. Suspended or revoking devices must remain reachable through the management plane so Guardian can wake them to fetch a pending `disconnect` command and report the result.

## Liveness and resource bounds

Guardian sends `keepalive` every 30 seconds. Server writes have a 10-second deadline so a dead or blocked client cannot hold a handler goroutine indefinitely.

The device is expected to apply a read deadline longer than the keepalive period and reconnect with bounded exponential backoff plus jitter. HTTP polling remains enabled independently, so loss of WebSocket connectivity never prevents command delivery.

## Scaling

The initial hub is process-local and appropriate for the current single Guardian application instance. The durable database remains the source of truth, so replacing the process-local publish step with Redis pub/sub for multi-instance deployments does not require any device protocol change.
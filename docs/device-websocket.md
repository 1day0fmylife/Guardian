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
## Service policy refresh (G-04)

The existing version 1 channel also sends
`{"type":"policy_changed","revision":42}`. This is a non-secret wake hint,
not authorization or a service list. Fetch `GET /api/v1/device/services` using
the device credential on enrollment, reconnect, and this hint. Catalog/grant/
membership changes broadcast only a revision; device lifecycle changes wake
the affected device. Hints coalesce to the highest revision independently of
command hints; failed and unchanged catalog mutations do not publish. Each
30-second keepalive checks the durable revision and credential validity, so
changes on another instance eventually refresh or close the channel.

Client contract (the device implementation lives outside Guardian):

- Keep a high-water revision. Ignore older hints and older HTTP responses.
  Apply a fetched policy atomically, including an empty service list.
- Only an authenticated response can authorize use of its listed endpoints.
  `mandatory_vpn=true` prohibits direct/WAN fallback. TLS remains required
  wherever the catalog specifies it; no trust bypass is introduced.
- Responses include UTC `generated_at` and `expires_at` (five minutes apart).
  Expiry is a lease bound, not a grant. Stop service use on expiry, suspension,
  revocation, authentication rejection or loss of VPN. Do not extend the lease
  locally after a failed refresh or an older response.
- Poll every 60 seconds even with WS connected, refresh before expiry, and use
  exponential retry delays of 1, 2, 4, 8, 16, then at most 30 seconds with jitter.
  Permit one fetch at a time; a newer hint during a fetch schedules another.
  A same-revision authenticated response may renew the lease with its supplied
  expiry. Unknown WS event types must be ignored by older clients.

Polling is required for missed hints, restart, and load-balanced instances.
No device agent is added to Guardian and no other repository is changed.

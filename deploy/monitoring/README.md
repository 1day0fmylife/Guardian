# Guardian monitoring (G-07)

The API exporter is opt-in, separate from public/admin/device ingress:

```sh
GUARDIAN_METRICS_LISTEN_ADDR=127.0.0.1:9097
GUARDIAN_GATEWAY_PROBE_ADDRESS=10.77.0.1:443
```

Set these in the existing systemd `guardian.env` file. The exporter accepts
literal loopback addresses only (including `[::1]`), serves `GET /metrics`, and
is not routed by Caddy. Run Prometheus or a local scrape agent in that same
host/network namespace. With containers, keep the scraper in the exporter
namespace or use a local forwarding agent; do not publish the exporter port
or move the unprivileged API into the host network to make it reachable.
The example Prometheus target is `127.0.0.1:9097`; install both YAML files under
`/etc/prometheus` or adapt the rule file path. No admin/device bearer token is
needed or exposed on this local exporter.

| Metric | Meaning |
| --- | --- |
| guardian_database_up | Bounded 2-second ping to the authoritative DB at scrape time |
| guardian_gateway_reachable | TCP connectivity to the one configured target; 30-second probes, 2-second deadline |
| guardian_gateway_last_probe_timestamp_seconds | 0 until a target is probed; disabled probes do not trigger an alert |
| guardian_operations_total | Success/error by five fixed operations (policy, gateway_probe, wireguard_reconcile, wireguard_peer_reconcile, telemetry_retention) |
| guardian_operation_duration_seconds | Fixed-bucket latency histogram for those operations |
| guardian_service_access_denials_total | Withheld service decisions seen during authenticated device policy fetches, by three known services and seven fixed reasons |
| guardian_policy_auth_denials_total | Device policy authentication failures, without identity/error labels |
| guardian_telemetry_deleted_total | Rows actually deleted by this API instance's configured retention worker |

Counters restart at process restart; Prometheus `rate`/`increase` handles resets.
Denials are policy evaluations, not packet counters or unique-device counts.
A TCP probe does not establish TLS trust, DAV/ACS authorization or service
health. It never changes grants or permits WAN fallback. Interface/URL/key/
address/device/user/request IDs and arbitrary error strings are not labels.
There are a fixed number of exported samples (including database_up), independent of
fleet size. Metrics use a small stdlib recorder and fixed Prometheus exposition;
no tracing/Redis dependency or privileged monitoring process is introduced.
The local wireguard counters remain zero when no local provider is configured.

`guardian.rules.yaml` alerts on exporter/DB failure, configured gateway outage,
WireGuard peer errors and configured retention errors. Choose alert routing and
receiver credentials in your deployment; none are stored in this repository.

Validation, using the official [Prometheus rule-test format](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/):

```sh
promtool check config prometheus.yaml
promtool check rules guardian.rules.yaml
promtool test rules guardian.rules.test.yaml
```

The exporter has a 5-second response deadline, while the scrape example uses
5 seconds and the DB probe 2 seconds. DB failures leave HTTP scrape available
with `guardian_database_up 0`. Do not equate `/healthz` liveness with `/readyz`
database readiness, nor `up == 1` with database/gateway health.

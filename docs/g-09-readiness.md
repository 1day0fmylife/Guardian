# G-09: measurements and readiness assessment

Scope agreed on 2026-10-10: measure first and assess readiness. This change
adds reproducible benchmarks and a decision gate, not a remote node agent or
multi-node failover. G-09 implementation acceptance remains open.

## Existing implementation and dependency gate

Reviewed main f9a89fe and G-08 d6d10ae. G-08 PR #15 has passing backend,
web, compose and service-gateway checks; it is still a dependency of this PR.
Main includes G-06/G-07. No duplicate catalog, RBAC, policy API, migration,
revocation or privileged network implementation is added.

The central API already has no network capabilities: compose drops all
capabilities and the API systemd unit has an empty CapabilityBoundingSet and
no WireGuard interface. The separate local reconciler retains CAP_NET_ADMIN,
uses the full Guardian binary, exposes a loopback HTTP listener, and accesses
the database directly. This is process separation, but not a bounded,
authenticated remote node protocol.

The ACL controller has a five-second pass context and 30-second kernel
membership expiry. Expiry prevents a stopped controller from preserving
access indefinitely. `service_acl_state.applied_revision` and peer applied
state describe one gateway. Acknowledgement from one of several gateways
would not prove revocation everywhere; these fields cannot safely be reused
as multi-node acknowledgements.

## Method

`BenchmarkServiceAccessSnapshot` uses an isolated migrated database with
100, 1,000 or 10,000 active peers, all three enabled service definitions and
three explicit individual allow grants per device. This deliberately dense
fixture exercises full grant evaluation, with no implicit access. Keys are
synthetic public data, endpoints use `.invalid`, and no credentials/private
keys are generated or returned. Fixture SQL is test-only; administrative
validation and audit behavior are not changed.

SQLite uses a temporary disk-backed database. PostgreSQL uses a disposable
schema selected by GUARDIAN_TEST_POSTGRES_URL, with cleanup after the run.
Use only a disposable test database, never production. Setup/migration is
outside the benchmark timer. Each timed snapshot verifies its target and
service counts. `BenchmarkGatewayProjection` measures binding verification
and deterministic nft script rendering from synthetic observed peers; it
excludes kernel observation, nft apply, network traffic and TLS.

Runs are sequential, three single-iteration snapshot samples per size and
three 100-iteration projection samples. These are exploratory local
baselines, not p95/p99, capacity certification or statistically significant
comparisons. No optimization is included. Host: Linux amd64, Intel i5-9300H
2.40GHz, eight logical CPUs, Go 1.25.4, PostgreSQL 16 Alpine via loopback.
CPU frequency, storage, caches and background host activity are uncontrolled.

```sh
go test ./internal/store -run '^$' -bench '^BenchmarkServiceAccessSnapshot/sqlite' -benchmem -benchtime=1x -count=3
# Set GUARDIAN_TEST_POSTGRES_URL securely to the disposable database URL.
go test ./internal/store -run '^$' -bench '^BenchmarkServiceAccessSnapshot/postgres' -benchmem -benchtime=1x -count=3
go test ./internal/gatewayacl -run '^$' -bench '^BenchmarkGatewayProjection' -benchmem -benchtime=100x -count=3
go test ./internal/store -run '^$' -bench '^BenchmarkServiceAccessSnapshot/sqlite/devices_1000$' -benchtime=10x -cpuprofile=/tmp/g09-cpu.pprof -o /tmp/g09-scale.test
go tool pprof -top /tmp/g09-scale.test /tmp/g09-cpu.pprof
```

## Decision gate before implementation

1. Obtain actual fleet size, active/revoked grant density, scope distribution,
   grant churn, telemetry/enrollment rates and peak concurrency. Measure on
   production-equivalent hardware using synthetic data and concurrent read,
   mutation and revocation workloads; capture end-to-end pass latency and
   expiry/revocation latency, database contention and resource saturation.
2. Specify availability SLO, tolerated outage and RTO/RPO, and choose an
   explicit failover topology. Throughput measurements cannot establish an
   HA requirement. G-01..08 must be merged and operationally stable, not just
   have passing local tests.
3. Profile and resolve demonstrated single-node bottlenecks first. Current
   snapshot evaluation scans all grants for each peer and each service:
   O(peers × services × grants). Replicating full snapshots onto more nodes
   does not remove this control-plane cost.
4. Design authenticated node identity, enrollment/rotation/revocation,
   per-node scoped snapshots and bounded commands; no arbitrary shell,
   database credentials or private keys in node-policy responses. Preserve
   API capability isolation, permission-based RBAC and deny-by-default.
5. Introduce per-node revision acknowledgements and monotonic lease epochs.
   A stale, partitioned or paused process must stop renewing kernel access
   when authority expires. Fence ingress/VIP ownership before failover;
   a database lease alone does not fence a live isolated gateway. Require
   revocation acknowledgement from every relevant node before address reuse.
6. Stage node crash, partition, restart, delayed/replayed/out-of-order policy,
   expired lease, clock behavior, stale acknowledgement and recovery tests.
   Node loss, malformed policy, missing grants or unauthorized node identity
   must never grant access. Test role denial, revocation during failover,
   legacy single-node compatibility and API CAP_NET_ADMIN=0.

Until these gates have evidence, retain the supported single-gateway model.

## Baseline results and conclusion

Median of three local samples (range in parentheses), milliseconds per pass:

| Devices | SQLite snapshot | PostgreSQL snapshot | Binding + render |
| --- | ---: | ---: | ---: |
| 100 | 4.35 (3.01–5.67) | 9.20 (9.19–10.23) | 0.111 (0.105–0.118) |
| 1,000 | 135.33 (125.27–142.70) | 156.65 (154.15–163.69) | 1.325 (1.310–1.383) |
| 10,000 | 23,487.67 (20,814.49–30,010.58) | 19,440.83 (16,093.68–20,578.63) | 19.906 (19.637–19.991) |

At 10,000 peers, snapshot allocations are approximately 53–55 MB and
580,000–810,000 allocations per pass. Raw successful outputs are in
`docs/benchmarks/g-09-*.txt`; interrupted previous-session runs are excluded.

A separate CPU profile of ten 1,000-peer SQLite iterations attributes 74.02%
of sampled CPU cumulatively to `domain.EvaluateServiceAccess` (22.06% flat).
The whole-process profile includes fixture setup and is an exploratory CPU
sample, not an off-CPU/database latency profile. The host Go installation
lacks its pprof executable; the captured Go 1.25.4 profile was read with the
already installed Go 1.24.11 pprof binary. No dependency was installed.

This confirms repeated grant evaluation is a significant CPU path in this
fixture. The 10,000-peer snapshot alone exceeds the five-second controller
pass budget; the CPU grant loop does not check context cancellation, so the
context deadline is not a hard execution bound for that loop. Indexing/grouping
grants and cancellation handling deserve a separately reviewed change, with
six or more before/after runs and security-equivalence tests. Do not silently
increase timeouts/leases to accommodate the workload.

The initial 1,000-device target is below the pass budget in these isolated
samples, but the full controller, concurrent mutations and traffic were not
measured. There is no evidence here that the deployed fleet requires HA or
that it supports a particular production SLO. Decision: keep remote-agent and
multi-node implementation deferred; collect real workload/availability needs
and address the measured control-plane path before choosing topology.

## Validation

- `go test ./...` with the disposable PostgreSQL URL: passed, including
  SQLite/PostgreSQL repository tests, HTTP authorization/negative/legacy
  policy behavior, permission-based RBAC, revocation, tenant isolation and
  gateway stale-revision/fail-closed recovery tests.
- `go vet ./...`, API build and `git diff --check`: passed.
- All three benchmark suites completed successfully; PostgreSQL schema
  fixtures are isolated and cleaned up. The initial sandbox-denied loopback
  attempt was rerun with authorized access and is not a measurement sample.
- Production code, API responses, migrations and default grants are unchanged.
  Existing G-08 real gateway CI is green; this assessment does not claim
  multi-node node-loss/failover acceptance.
- Race detector: both database benchmark fixtures at 100 devices and all
  gateway ACL tests plus the 100-device projection benchmark passed. Race
  measurements are excluded from the baseline table.

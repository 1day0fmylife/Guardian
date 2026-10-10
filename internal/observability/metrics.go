// Package observability exports only a fixed, credential-free metric vocabulary.
package observability

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

var operations = [...]string{"policy", "gateway_probe", "wireguard_reconcile", "wireguard_peer_reconcile", "telemetry_retention"}
var buckets = [...]float64{.005, .025, .1, .5, 2, 10}
var reasons = [...]string{"no_grant", "service_disabled", "device_not_active", "tenant_deny", "site_deny", "group_deny", "device_deny"}

type operation struct {
	success, failures atomic.Uint64
	count             atomic.Uint64
	micros            atomic.Uint64
	buckets           [len(buckets)]atomic.Uint64
}

type Metrics struct {
	ops            [len(operations)]operation
	denials        [3][len(reasons)]atomic.Uint64
	authDenied     atomic.Uint64
	deleted        atomic.Uint64
	gatewayUp      atomic.Int64
	gatewayChecked atomic.Int64
}

// Observe measures completed operations; arbitrary operation strings are ignored.
// rate(guardian_operations_total{result="error"}[5m])
// histogram_quantile(0.99, sum by (le, operation) (rate(guardian_operation_duration_seconds_bucket[5m])))
func (m *Metrics) Observe(name string, started time.Time, err error) {
	if m == nil {
		return
	}
	for i, known := range operations {
		if name != known {
			continue
		}
		op := &m.ops[i]
		if err == nil {
			op.success.Add(1)
		} else {
			op.failures.Add(1)
		}
		elapsed := time.Since(started)
		if elapsed < 0 {
			elapsed = 0
		}
		op.count.Add(1)
		op.micros.Add(uint64(elapsed.Microseconds()))
		for j, bound := range buckets {
			if elapsed.Seconds() <= bound {
				op.buckets[j].Add(1)
			}
		}
		return
	}
}

// Denied counts withheld decisions during policy fetches, not packets or unique devices.
// sum by (service, reason) (rate(guardian_service_access_denials_total[5m]))
func (m *Metrics) Denied(service, reason string) {
	if m == nil {
		return
	}
	for i, id := range domain.KnownServiceIDs() {
		if service != id {
			continue
		}
		for j, known := range reasons {
			if reason == known {
				m.denials[i][j].Add(1)
				return
			}
		}
	}
}
func (m *Metrics) AuthenticationDenied() {
	if m != nil {
		m.authDenied.Add(1)
	}
}
func (m *Metrics) TelemetryDeleted(n int64) {
	if m != nil && n > 0 {
		m.deleted.Add(uint64(n))
	}
}

// Write exports bounded Prometheus text without identifiers, URLs or error strings.
func (m *Metrics) Write(w io.Writer) {
	fmt.Fprintln(w, "# HELP guardian_operations_total Completed operations by fixed operation and result.\n# TYPE guardian_operations_total counter")
	for i, name := range operations {
		op := &m.ops[i]
		fmt.Fprintf(w, "guardian_operations_total{operation=%q,result=\"success\"} %d\nguardian_operations_total{operation=%q,result=\"error\"} %d\n", name, op.success.Load(), name, op.failures.Load())
	}
	fmt.Fprintln(w, "# HELP guardian_operation_duration_seconds Operation duration.\n# TYPE guardian_operation_duration_seconds histogram")
	for i, name := range operations {
		op := &m.ops[i]
		for j, bound := range buckets {
			fmt.Fprintf(w, "guardian_operation_duration_seconds_bucket{operation=%q,le=\"%g\"} %d\n", name, bound, op.buckets[j].Load())
		}
		fmt.Fprintf(w, "guardian_operation_duration_seconds_bucket{operation=%q,le=\"+Inf\"} %d\nguardian_operation_duration_seconds_count{operation=%q} %d\nguardian_operation_duration_seconds_sum{operation=%q} %g\n", name, op.count.Load(), name, op.count.Load(), name, float64(op.micros.Load())/1e6)
	}
	fmt.Fprintln(w, "# HELP guardian_service_access_denials_total Withheld decisions on device policy fetches.\n# TYPE guardian_service_access_denials_total counter")
	for i, id := range domain.KnownServiceIDs() {
		for j, reason := range reasons {
			fmt.Fprintf(w, "guardian_service_access_denials_total{service=%q,reason=%q} %d\n", id, reason, m.denials[i][j].Load())
		}
	}
	fmt.Fprintf(w, "# TYPE guardian_policy_auth_denials_total counter\nguardian_policy_auth_denials_total %d\n# TYPE guardian_telemetry_deleted_total counter\nguardian_telemetry_deleted_total %d\n# TYPE guardian_gateway_reachable gauge\nguardian_gateway_reachable %d\n# TYPE guardian_gateway_last_probe_timestamp_seconds gauge\nguardian_gateway_last_probe_timestamp_seconds %d\n", m.authDenied.Load(), m.deleted.Load(), m.gatewayUp.Load(), m.gatewayChecked.Load())
}

type Pinger interface{ Ping(context.Context) error }

func (m *Metrics) Handler(database Pinger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		up := 1
		if database.Ping(ctx) != nil {
			up = 0
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		m.Write(w)
		fmt.Fprintf(w, "# TYPE guardian_database_up gauge\nguardian_database_up %d\n", up)
	})
	return mux
}

// ProbeGateway checks TCP connectivity only. It does not bypass or test TLS/auth.
func (m *Metrics) ProbeGateway(ctx context.Context, target string) error {
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", target)
	if conn != nil {
		_ = conn.Close()
	}
	up := int64(0)
	if err == nil {
		up = 1
	}
	m.gatewayUp.Store(up)
	m.gatewayChecked.Store(time.Now().Unix())
	m.Observe("gateway_probe", started, err)
	return err
}

package observability

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type failingDatabase struct{}

func (failingDatabase) Ping(context.Context) error { return errors.New("password=secret-canary") }

func TestMetricsBoundedVocabularyAndConcurrentUpdates(t *testing.T) {
	m := &Metrics{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Observe("policy", time.Now(), nil)
			m.Denied("sunkardav", "no_grant")
			m.AuthenticationDenied()
		}()
	}
	wg.Wait()
	m.Observe("secret-device-id", time.Now(), errors.New("secret-password"))
	m.Denied("secret-device-id", "secret-reason")
	m.Denied("sunkardav", "secret-reason")
	var out bytes.Buffer
	m.Write(&out)
	body := out.String()
	for _, forbidden := range []string{"secret", "device_id=", "address=", "url=", "token=", "password="} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metric vocabulary leaked %q", forbidden)
		}
	}
	if !strings.Contains(body, `guardian_service_access_denials_total{service="sunkardav",reason="no_grant"} 20`) {
		t.Fatal("policy denials not recorded")
	}
	lines := strings.Split(body, "\n")
	if len(lines) > 120 {
		t.Fatalf("metric cardinality = %d lines, want <=120", len(lines))
	}
	rec := httptest.NewRecorder()
	m.Handler(failingDatabase{}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "guardian_database_up 0") || strings.Contains(rec.Body.String(), "canary") {
		t.Fatalf("unavailable DB scrape = %d, expected safe up=0", rec.Code)
	}
}

func TestGatewayReachabilityAndFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := listener.Addr().String()
	m := &Metrics{}
	if err := m.ProbeGateway(context.Background(), target); err != nil || m.gatewayUp.Load() != 1 {
		t.Fatalf("ProbeGateway live = %v; want reachable", err)
	}
	listener.Close()
	if err := m.ProbeGateway(context.Background(), target); err == nil || m.gatewayUp.Load() != 0 {
		t.Fatalf("ProbeGateway stopped = %v; want unreachable", err)
	}
	listener, err = net.Listen("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := m.ProbeGateway(context.Background(), target); err != nil || m.gatewayUp.Load() != 1 {
		t.Fatalf("ProbeGateway recovered = %v; want reachable", err)
	}
	if m.ops[1].failures.Load() != 1 || m.gatewayChecked.Load() == 0 {
		t.Fatal("failed gateway probe not measured")
	}
}

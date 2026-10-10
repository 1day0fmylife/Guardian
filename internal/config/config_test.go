package config

import "testing"

func TestMetricsListenerAndRetentionValidation(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:9090", "192.0.2.1:9090", "localhost:9090", "127.0.0.1:0", "127.0.0.1:65536"} {
		t.Run(addr, func(t *testing.T) {
			t.Setenv("GUARDIAN_METRICS_LISTEN_ADDR", addr)
			if _, err := Load(); err == nil {
				t.Fatalf("Load(%q) accepted non-loopback/invalid metrics binding", addr)
			}
		})
	}
	for _, addr := range []string{"", "127.0.0.1:9090", "[::1]:9090"} {
		t.Run("valid-"+addr, func(t *testing.T) {
			t.Setenv("GUARDIAN_METRICS_LISTEN_ADDR", addr)
			cfg, err := Load()
			if err != nil || cfg.TelemetryRetentionAge != 0 {
				t.Fatalf("Load(%q) = %v; want opt-in retention", addr, err)
			}
		})
	}
	for _, age := range []string{"-1h", "1h", "999999h", "broken"} {
		t.Run(age, func(t *testing.T) {
			t.Setenv("GUARDIAN_TELEMETRY_RETENTION_AGE", age)
			if _, err := Load(); err == nil {
				t.Fatalf("Load(%q) accepted invalid retention age", age)
			}
		})
	}
}

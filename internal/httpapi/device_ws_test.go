package httpapi

import (
	"net/http"
	"testing"
	"time"
)

func TestDeviceSignalHubPublishesWithoutDurableState(t *testing.T) {
	hub := newDeviceSignalHub()
	signals, unsubscribe := hub.subscribe("device-1")
	defer unsubscribe()

	hub.publish("device-1", deviceSignal{Type: "commands_available"})
	select {
	case signal := <-signals:
		if signal.Type != "commands_available" {
			t.Fatalf("signal type = %q", signal.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("device signal was not delivered")
	}

	// Publishing for another device must not wake this subscriber.
	hub.publish("device-2", deviceSignal{Type: "commands_available"})
	select {
	case signal := <-signals:
		t.Fatalf("unexpected cross-device signal: %+v", signal)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestDeviceMutationSignal(t *testing.T) {
	tests := []struct {
		method, path string
		deviceID     string
		signal       string
		ok           bool
	}{
		{http.MethodPost, "/api/v1/devices/dev-1/commands", "dev-1", "commands_available", true},
		{http.MethodPost, "/api/v1/devices/dev-1/suspend", "dev-1", "commands_available", true},
		{http.MethodPost, "/api/v1/devices/dev-1/resume", "dev-1", "commands_available", true},
		{http.MethodPost, "/api/v1/devices/dev-1/revoke", "dev-1", "commands_available", true},
		{http.MethodPost, "/api/v1/devices/dev-1/credentials/revoke", "dev-1", "reauth_required", true},
		{http.MethodGet, "/api/v1/devices/dev-1/commands", "", "", false},
		{http.MethodPost, "/api/v1/devices//commands", "", "", false},
		{http.MethodPost, "/api/v1/device/commands", "", "", false},
	}
	for _, test := range tests {
		deviceID, signal, ok := deviceMutationSignal(test.method, test.path)
		if deviceID != test.deviceID || signal != test.signal || ok != test.ok {
			t.Fatalf("deviceMutationSignal(%q, %q) = (%q, %q, %v), want (%q, %q, %v)",
				test.method, test.path, deviceID, signal, ok, test.deviceID, test.signal, test.ok)
		}
	}
}

func TestDeviceSignalHubCoalescesSlowConsumer(t *testing.T) {
	hub := newDeviceSignalHub()
	signals, unsubscribe := hub.subscribe("device-1")
	defer unsubscribe()

	for i := 0; i < 100; i++ {
		hub.publish("device-1", deviceSignal{Type: "commands_available"})
	}

	count := 0
	for {
		select {
		case <-signals:
			count++
		default:
			if count == 0 || count > 2 {
				t.Fatalf("coalesced signal count = %d", count)
			}
			return
		}
	}
}

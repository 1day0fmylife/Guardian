package wireguard

import (
	"context"
	"net"
	"testing"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeWGControlClient struct {
	device  *wgtypes.Device
	configs []wgtypes.Config
}

func (f *fakeWGControlClient) Device(string) (*wgtypes.Device, error) { return f.device, nil }
func (f *fakeWGControlClient) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	f.configs = append(f.configs, cfg)
	return nil
}
func (f *fakeWGControlClient) Close() error { return nil }

func testProviderKey(seed byte) string {
	var key wgtypes.Key
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key.String()
}

func TestWGCtrlProviderUpsertRemovesPreviousKeyAndUsesHostRoute(t *testing.T) {
	client := &fakeWGControlClient{device: &wgtypes.Device{Name: "wg0"}}
	provider := newWGCtrlProviderWithClient("wg0", client)
	item := domain.WireGuardReconcileItem{
		PublicKey: testProviderKey(1), PreviousPublicKey: testProviderKey(2), AssignedAddress: "10.88.0.20",
	}
	if err := provider.UpsertPeer(context.Background(), item); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}
	if len(client.configs) != 1 || len(client.configs[0].Peers) != 2 {
		t.Fatalf("configs = %+v", client.configs)
	}
	remove := client.configs[0].Peers[0]
	if !remove.Remove || remove.PublicKey.String() != item.PreviousPublicKey {
		t.Fatalf("previous peer removal = %+v", remove)
	}
	upsert := client.configs[0].Peers[1]
	if upsert.Remove || !upsert.ReplaceAllowedIPs || upsert.PublicKey.String() != item.PublicKey {
		t.Fatalf("desired peer config = %+v", upsert)
	}
	if len(upsert.AllowedIPs) != 1 || upsert.AllowedIPs[0].String() != "10.88.0.20/32" {
		t.Fatalf("allowed IPs = %v", upsert.AllowedIPs)
	}
	if client.configs[0].PrivateKey != nil {
		t.Fatal("provider must never configure the server private key")
	}
}

func TestWGCtrlProviderRemoveDeletesCurrentAndPreviousKeys(t *testing.T) {
	client := &fakeWGControlClient{device: &wgtypes.Device{Name: "wg0"}}
	provider := newWGCtrlProviderWithClient("wg0", client)
	item := domain.WireGuardReconcileItem{PublicKey: testProviderKey(3), PreviousPublicKey: testProviderKey(4)}
	if err := provider.RemovePeer(context.Background(), item); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if len(client.configs) != 1 || len(client.configs[0].Peers) != 2 {
		t.Fatalf("configs = %+v", client.configs)
	}
	for _, peer := range client.configs[0].Peers {
		if !peer.Remove {
			t.Fatalf("remove peer config = %+v", peer)
		}
	}
}

func TestPeerAllowedIPNormalizesToIPv4HostRoute(t *testing.T) {
	for _, input := range []string{"10.0.0.8", "10.0.0.8/24", "10.0.0.8/32"} {
		got, err := peerAllowedIP(input)
		if err != nil {
			t.Fatalf("peerAllowedIP(%q): %v", input, err)
		}
		want := net.IPNet{IP: net.ParseIP("10.0.0.8").To4(), Mask: net.CIDRMask(32, 32)}
		if got.String() != want.String() {
			t.Fatalf("peerAllowedIP(%q) = %s, want %s", input, got.String(), want.String())
		}
	}
}

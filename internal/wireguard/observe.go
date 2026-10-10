package wireguard

import (
	"context"
	"fmt"
	"net/netip"
)

// ObservedPeer is what the kernel actually holds for one WireGuard peer. Only
// public material is exposed: public key and the allowed-ips that bind the
// peer's source addresses (cryptokey routing).
type ObservedPeer struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
}

// PeerObserver reports the peers currently configured on the interface.
type PeerObserver interface {
	ObservePeers(ctx context.Context) ([]ObservedPeer, error)
}

// ObservePeers reads the live peer table of the interface. It never returns
// private or preshared keys.
func (p *WGCtrlProvider) ObservePeers(_ context.Context) ([]ObservedPeer, error) {
	device, err := p.client.Device(p.interfaceName)
	if err != nil {
		return nil, fmt.Errorf("read WireGuard interface %s: %w", p.interfaceName, err)
	}
	out := make([]ObservedPeer, 0, len(device.Peers))
	for _, peer := range device.Peers {
		observed := ObservedPeer{PublicKey: peer.PublicKey.String()}
		for _, allowed := range peer.AllowedIPs {
			addr, ok := netip.AddrFromSlice(allowed.IP)
			if !ok {
				continue
			}
			ones, bits := allowed.Mask.Size()
			if bits == 0 {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() && bits == 128 {
				ones -= 96 // IPv4 mask carried in a 16-byte form
			}
			prefix, err := addr.Prefix(ones)
			if err != nil {
				continue
			}
			observed.AllowedIPs = append(observed.AllowedIPs, prefix)
		}
		out = append(out, observed)
	}
	return out, nil
}

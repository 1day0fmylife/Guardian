package gatewayacl

import (
	"net/netip"
	"sort"

	"github.com/1day0fmylife/Guardian/internal/store"
	"github.com/1day0fmylife/Guardian/internal/wireguard"
)

// Reasons a Guardian-attested binding is not honored by the gateway.
const (
	// RejectPeerNotInterface: the kernel has no peer with the attested key
	// (removed, not yet reconciled, or rotated away).
	RejectPeerNotInterface = "peer_not_in_interface"
	// RejectAllowedIPsMismatch: the kernel peer's allowed-ips are not exactly
	// the attested tunnel address as a host route (wrong address, extra
	// prefixes such as a whole subnet, or none).
	RejectAllowedIPsMismatch = "allowed_ips_mismatch"
	// RejectAddressClaimedByOther: another kernel peer also routes the
	// attested address.
	RejectAddressClaimedByOther = "address_claimed_by_other_peer"
)

// Rejection explains why one device's grant was withheld from the gateway.
type Rejection struct {
	DeviceID string
	Reason   string
}

// VerifyBindings keeps only the targets whose Guardian-attested binding
// (device id <-> WireGuard public key <-> single tunnel host address) is the
// binding the kernel actually enforces through WireGuard cryptokey routing.
//
// Source addresses on the tunnel are only trustworthy because WireGuard
// drops packets whose source is not inside the allowed-ips of the peer that
// authenticated them. A grant is therefore attached to an address only when
// that peer key is present and is the *sole* route for exactly that /32.
// Anything else (removed peer, stale key during rotation, address reassigned
// but not yet reconciled, widened allowed-ips) is denied until the kernel
// matches Guardian's record again. Unknown kernel peers never receive grants
// because they have no target; they are returned as unexpected for
// diagnostics only.
func VerifyBindings(targets []store.ServiceAccessTarget, observed []wireguard.ObservedPeer) (verified []store.ServiceAccessTarget, rejected []Rejection, unexpected []string) {
	byKey := make(map[string]wireguard.ObservedPeer, len(observed))
	routes := map[netip.Prefix][]string{}
	for _, peer := range observed {
		byKey[peer.PublicKey] = peer
		for _, prefix := range peer.AllowedIPs {
			routes[prefix] = append(routes[prefix], peer.PublicKey)
		}
	}
	expectedKeys := make(map[string]bool, len(targets))
	for _, target := range targets {
		expectedKeys[target.PublicKey] = true
	}

	for _, target := range targets {
		peer, ok := byKey[target.PublicKey]
		if !ok {
			rejected = append(rejected, Rejection{DeviceID: target.DeviceID, Reason: RejectPeerNotInterface})
			continue
		}
		host := netip.PrefixFrom(target.Address, target.Address.BitLen())
		if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != host {
			rejected = append(rejected, Rejection{DeviceID: target.DeviceID, Reason: RejectAllowedIPsMismatch})
			continue
		}
		if len(routes[host]) != 1 {
			rejected = append(rejected, Rejection{DeviceID: target.DeviceID, Reason: RejectAddressClaimedByOther})
			continue
		}
		verified = append(verified, target)
	}

	for _, peer := range observed {
		if !expectedKeys[peer.PublicKey] {
			unexpected = append(unexpected, peer.PublicKey)
		}
	}
	sort.Strings(unexpected)
	return verified, rejected, unexpected
}

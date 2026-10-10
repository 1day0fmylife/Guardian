package gatewayacl

import (
	"fmt"
	"github.com/1day0fmylife/Guardian/internal/store"
	"github.com/1day0fmylife/Guardian/internal/wireguard"
	"net/netip"
	"testing"
)

// BenchmarkGatewayProjection excludes kernel observation, nft apply and traffic.
func BenchmarkGatewayProjection(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("devices_%d", n), func(b *testing.B) {
			targets := make([]store.ServiceAccessTarget, n)
			observed := make([]wireguard.ObservedPeer, n)
			for i := range targets {
				addr := netip.MustParseAddr(fmt.Sprintf("10.246.%d.%d", (i+2)/256, (i+2)%256))
				key := fmt.Sprintf("synthetic-public-%d", i)
				targets[i] = store.ServiceAccessTarget{DeviceID: key, PeerID: key, PublicKey: key, Address: addr, ConfigRevision: 1, AppliedRevision: 1, ServiceIDs: allServices}
				observed[i] = wireguard.ObservedPeer{PublicKey: key, AllowedIPs: []netip.Prefix{netip.PrefixFrom(addr, 32)}}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				verified, rejected, unexpected := VerifyBindings(targets, observed)
				if len(verified) != n || len(rejected) != 0 || len(unexpected) != 0 {
					b.Fatal("invalid binding fixture")
				}
				script, err := Render("guardian_gw", allServices, verified)
				if err != nil || script == "" {
					b.Fatalf("render: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(n), "devices")
		})
	}
}

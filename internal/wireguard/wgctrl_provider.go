package wireguard

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgControlClient interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Close() error
}

type WGCtrlProvider struct {
	interfaceName string
	client        wgControlClient
}

func NewWGCtrlProvider(interfaceName string) (*WGCtrlProvider, error) {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return nil, fmt.Errorf("WireGuard interface name is required")
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl client: %w", err)
	}
	provider := &WGCtrlProvider{interfaceName: interfaceName, client: client}
	if _, err := client.Device(interfaceName); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("open WireGuard interface %q: %w", interfaceName, err)
	}
	return provider, nil
}

func newWGCtrlProviderWithClient(interfaceName string, client wgControlClient) *WGCtrlProvider {
	return &WGCtrlProvider{interfaceName: interfaceName, client: client}
}

func (p *WGCtrlProvider) Close() error {
	if p == nil || p.client == nil {
		return nil
	}
	return p.client.Close()
}

func (p *WGCtrlProvider) UpsertPeer(_ context.Context, item domain.WireGuardReconcileItem) error {
	currentKey, err := wgtypes.ParseKey(strings.TrimSpace(item.PublicKey))
	if err != nil {
		return fmt.Errorf("parse desired WireGuard public key: %w", err)
	}
	allowedIP, err := peerAllowedIP(item.AssignedAddress)
	if err != nil {
		return err
	}

	peers := make([]wgtypes.PeerConfig, 0, 2)
	if previous := strings.TrimSpace(item.PreviousPublicKey); previous != "" && previous != item.PublicKey {
		previousKey, err := wgtypes.ParseKey(previous)
		if err != nil {
			return fmt.Errorf("parse previous WireGuard public key: %w", err)
		}
		peers = append(peers, wgtypes.PeerConfig{PublicKey: previousKey, Remove: true})
	}
	peers = append(peers, wgtypes.PeerConfig{
		PublicKey:         currentKey,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{allowedIP},
	})
	if err := p.client.ConfigureDevice(p.interfaceName, wgtypes.Config{Peers: peers}); err != nil {
		return fmt.Errorf("configure WireGuard peer on %s: %w", p.interfaceName, err)
	}
	return nil
}

func (p *WGCtrlProvider) RemovePeer(_ context.Context, item domain.WireGuardReconcileItem) error {
	keys := []string{strings.TrimSpace(item.PublicKey), strings.TrimSpace(item.PreviousPublicKey)}
	peers := make([]wgtypes.PeerConfig, 0, len(keys))
	seen := make(map[wgtypes.Key]struct{}, len(keys))
	for _, raw := range keys {
		if raw == "" {
			continue
		}
		key, err := wgtypes.ParseKey(raw)
		if err != nil {
			return fmt.Errorf("parse WireGuard public key for removal: %w", err)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		peers = append(peers, wgtypes.PeerConfig{PublicKey: key, Remove: true})
	}
	if len(peers) == 0 {
		return fmt.Errorf("no WireGuard public key available for peer removal")
	}
	if err := p.client.ConfigureDevice(p.interfaceName, wgtypes.Config{Peers: peers}); err != nil {
		return fmt.Errorf("remove WireGuard peer from %s: %w", p.interfaceName, err)
	}
	return nil
}

func peerAllowedIP(address string) (net.IPNet, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return net.IPNet{}, fmt.Errorf("assigned WireGuard address is required")
	}
	if strings.Contains(address, "/") {
		ip, _, err := net.ParseCIDR(address)
		if err != nil {
			return net.IPNet{}, fmt.Errorf("parse assigned WireGuard address: %w", err)
		}
		if ip4 := ip.To4(); ip4 != nil {
			return net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
		}
		return net.IPNet{}, fmt.Errorf("assigned WireGuard address must be IPv4")
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return net.IPNet{}, fmt.Errorf("assigned WireGuard address must be a valid IPv4 address")
	}
	return net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
}

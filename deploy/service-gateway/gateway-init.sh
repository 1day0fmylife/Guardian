#!/bin/sh
# Brings up the WireGuard interface, the service VIPs and the nftables
# ruleset of the service gateway, then stays alive so sibling containers can
# share this network namespace. Peers are added by the Guardian reconciler,
# never here. The server private key is read from a file and never logged.
set -eu

: "${WG_INTERFACE:=wg0}"
: "${WG_PORT:=51820}"
: "${WG_ADDRESS:?WG_ADDRESS is required (e.g. 10.77.0.1/24)}"
: "${WG_MTU:=1380}"
: "${WG_PRIVATE_KEY_FILE:=/run/secrets/wg_private_key}"
: "${TUNNEL_CIDR:?TUNNEL_CIDR is required}"
: "${VIP_DNS:?}" "${VIP_DAV:?}" "${VIP_FLEET:?}" "${VIP_ACS:?}"
: "${NFT_TABLE:=guardian_gw}"

[ -r "$WG_PRIVATE_KEY_FILE" ] || { echo "WireGuard private key file is not readable" >&2; exit 1; }

if ! ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
    ip link add dev "$WG_INTERFACE" type wireguard
fi
wg set "$WG_INTERFACE" private-key "$WG_PRIVATE_KEY_FILE" listen-port "$WG_PORT"
ip address replace "$WG_ADDRESS" dev "$WG_INTERFACE"
ip link set dev "$WG_INTERFACE" mtu "$WG_MTU" up

# Service addresses live on loopback: they are local destinations of the
# gateway, so tunnel traffic to them is INPUT, never forwarded.
for vip in "$VIP_DNS" "$VIP_DAV" "$VIP_FLEET" "$VIP_ACS"; do
    ip address replace "$vip/32" dev lo
done

WG_ADDRESS_HOST=${WG_ADDRESS%/*}
export WG_INTERFACE WG_PORT TUNNEL_CIDR VIP_DNS VIP_DAV VIP_FLEET VIP_ACS NFT_TABLE WG_ADDRESS_HOST
envsubst '${WG_INTERFACE} ${WG_PORT} ${TUNNEL_CIDR} ${VIP_DNS} ${VIP_DAV} ${VIP_FLEET} ${VIP_ACS} ${NFT_TABLE} ${WG_ADDRESS_HOST}' \
    < /etc/guardian-gateway/nftables.conf.tmpl > /run/guardian-gateway.nft
nft -c -f /run/guardian-gateway.nft
nft -f /run/guardian-gateway.nft

# Remove only this optional profile's old NAT table when returning to defaults.
if nft list table ip "${NFT_TABLE}_cr_nat" >/dev/null 2>&1; then
    nft delete table ip "${NFT_TABLE}_cr_nat"
fi
if [ -n "${CWMP_CR_BACKEND_ADDRESS:-}" ]; then
    : "${CWMP_CR_BACKEND_INTERFACE:?explicit backend interface required for CR}"
    : "${CWMP_CR_SOURCE:?explicit ACS VIP source required for CR}"
    [ "$CWMP_CR_SOURCE" = "$VIP_ACS" ] || { echo "CR source must equal ACS VIP" >&2; exit 1; }
    case "$CWMP_CR_BACKEND_INTERFACE" in *[!a-zA-Z0-9_.-]*|"") echo "invalid CR interface" >&2; exit 1;; esac
    case "$CWMP_CR_BACKEND_ADDRESS" in *[!0-9.]*|"") echo "invalid CR backend address" >&2; exit 1;; esac
    case "$CWMP_CR_BACKEND_ADDRESS" in 10.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2[0-9].*|172.30.*|172.31.*) ;; *) echo "CR backend must be private IPv4" >&2; exit 1;; esac
    export CWMP_CR_BACKEND_ADDRESS CWMP_CR_BACKEND_INTERFACE
    envsubst '${WG_INTERFACE} ${NFT_TABLE} ${VIP_ACS} ${CWMP_CR_BACKEND_ADDRESS} ${CWMP_CR_BACKEND_INTERFACE}' \
        < /etc/guardian-gateway/cwmp-cr.nft.tmpl > /run/guardian-cwmp-cr.nft
    nft -c -f /run/guardian-cwmp-cr.nft
    nft -f /run/guardian-cwmp-cr.nft
    echo 1 > /proc/sys/net/ipv4/ip_forward
fi

touch /run/gateway-ready
echo "gateway ready: interface=$WG_INTERFACE table=$NFT_TABLE"

trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done

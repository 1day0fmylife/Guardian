#!/usr/bin/env bash
# Test helper executed inside the gateway image on the `public` network.
# Modes: admin-setup | admin-revoke | admin-suspend | client | public-probe
# Used only by scripts/verify.sh; it generates throw-away test keys.
set -uo pipefail

mode=${1:?mode}
fail=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; fail=1; }
log()  { echo "$*" >&2; }

api() { # method path [json]
    local method=$1 path=$2 body=${3:-}
    local args=(-sk --max-time 20 -X "$method" -H "Authorization: Bearer ${ADMIN_TOKEN:-}" -H 'Content-Type: application/json')
    [[ -n "$body" ]] && args+=(-d "$body")
    curl "${args[@]}" "$API$path"
}

case "$mode" in
admin-setup)
    : "${API:?}" "${ENROLL:?}" "${SERVER_PUBLIC_KEY:?}" "${WG_ENDPOINT:?}" "${TUNNEL_CIDR:?}" "${WG_ADDRESS:?}"
    : "${VIP_NET:?}" "${VIP_DNS:?}" "${DAV_FQDN:?}" "${FLEET_FQDN:?}" "${ACS_FQDN:?}"
    for _ in $(seq 1 60); do curl -sk --max-time 3 "$API/healthz" >/dev/null && break; sleep 1; done

    boot=$(curl -sk -X POST "$API/api/v1/auth/bootstrap" -H 'Content-Type: application/json' \
        -d '{"username":"gwtest","display_name":"Gateway test","password":"gateway-test-password-0123456789"}')
    ADMIN_TOKEN=$(jq -r .token <<<"$boot")
    [[ -n "$ADMIN_TOKEN" && "$ADMIN_TOKEN" != null ]] || { log "bootstrap failed: $boot"; exit 1; }
    API_BASE=$API; API="$API_BASE"

    pool=$(api POST /api/v1/address-pools "$(jq -nc --arg c "$TUNNEL_CIDR" --arg g "${WG_ADDRESS%/*}" --arg d "$VIP_DNS" \
        '{name:"gw-test",cidr:$c,gateway:$g,dns_servers:[$d]}')")
    pool_id=$(jq -r .id <<<"$pool")
    profile=$(api POST /api/v1/vpn-profiles "$(jq -nc --arg k "$SERVER_PUBLIC_KEY" --arg e "$WG_ENDPOINT" --arg n "$VIP_NET" \
        --arg d "$VIP_DNS" --arg p "$pool_id" \
        '{name:"gw-test",server_public_key:$k,endpoint:$e,allowed_ips:[$n],dns_servers:[$d],persistent_keepalive:1,address_pool_id:$p}')")
    profile_id=$(jq -r .id <<<"$profile")
    [[ "$profile_id" != null ]] || { log "profile failed: $profile"; exit 1; }

    for pair in "sunkardav:$DAV_FQDN" "admiral-device:$FLEET_FQDN" "sunkarcwmp-acs:$ACS_FQDN"; do
        id=${pair%%:*}; fqdn=${pair#*:}
        cur=$(api GET "/api/v1/services/$id")
        body=$(jq -c --arg f "$fqdn" '{expected_revision:.revision,display_name,internal_dns_name:$f,protocol,port,tls_policy,allowed_scopes,enabled:true}' <<<"$cur")
        res=$(api PUT "/api/v1/services/$id" "$body")
        [[ $(jq -r .service.enabled <<<"$res") == true ]] || { log "enable $id failed: $res"; exit 1; }
    done

    clients='[]'
    # name:granted service ids (comma separated)
    for spec in "a:sunkardav" "b:sunkarcwmp-acs,admiral-device"; do
        name=${spec%%:*}; granted=${spec#*:}
        priv=$(wg genkey); pub=$(wg pubkey <<<"$priv")
        enr=$(api POST /api/v1/enrollments "$(jq -nc --arg u "gw-$name-$RANDOM" --arg p "$profile_id" \
            '{name:"gateway test",profile_id:$p,bound_device_uuid:$u,ttl_seconds:600}')")
        token=$(jq -r .token <<<"$enr"); uuid=$(jq -r .enrollment.bound_device_uuid <<<"$enr")
        claim=$(curl -sk -X POST "$ENROLL/api/v1/device/enroll" -H "Authorization: Guardian-Enrollment $token" \
            -H 'Content-Type: application/json' \
            -d "$(jq -nc --arg u "$uuid" --arg n "gw-$name" --arg k "$pub" '{device_uuid:$u,device_name:$n,public_key:$k}')")
        dev=$(jq -r .device.id <<<"$claim"); addr=$(jq -r .wireguard.assigned_address <<<"$claim")
        [[ "$dev" != null && "$addr" != null ]] || { log "enrollment of $name failed: $claim"; exit 1; }
        IFS=, read -ra svcs <<<"$granted"
        for svc in "${svcs[@]}"; do
            res=$(api POST "/api/v1/services/$svc/grants" "$(jq -nc --arg d "$dev" '{scope_type:"device",scope_id:$d,effect:"allow"}')")
            [[ $(jq -r .grant.effect <<<"$res") == allow ]] || { log "grant $svc->$name failed: $res"; exit 1; }
        done
        clients=$(jq -c --arg n "$name" --arg d "$dev" --arg k "$priv" --arg a "$addr" --arg g "$granted" \
            '. + [{name:$n,device_id:$d,private_key:$k,address:$a,granted:($g|split(","))}]' <<<"$clients")
    done
    jq -nc --arg t "$ADMIN_TOKEN" --argjson c "$clients" '{admin_token:$t,clients:$c}'
    ;;

admin-revoke)
    : "${API:?}" "${ADMIN_TOKEN:?}" "${DEVICE_ID:?}"
    api POST "/api/v1/devices/$DEVICE_ID/revoke" | jq -c .
    ;;

admin-suspend)
    : "${API:?}" "${ADMIN_TOKEN:?}" "${DEVICE_ID:?}"
    api POST "/api/v1/devices/$DEVICE_ID/suspend" | jq -c .
    ;;

public-probe)
    : "${TARGET:?}"
    for port in 443 80 8080 8081 8443 53; do
        if curl -sk --max-time 3 "https://$TARGET:$port/" >/dev/null 2>&1 || curl -s --max-time 3 "http://$TARGET:$port/" >/dev/null 2>&1; then
            bad "public side answered on tcp/$port"
        else
            pass "public side tcp/$port unreachable"
        fi
    done
    if dig +time=2 +tries=1 +short @"$TARGET" "${ACS_FQDN:-acs.internal}" 2>/dev/null | grep -q .; then
        bad "public side answered DNS on udp/53"
    else
        pass "public side udp/53 unreachable"
    fi
    for host in sunkardav admiral sunkarcwmp-acs postgres guardian-api; do
        if getent hosts "$host" >/dev/null; then bad "public network resolves internal host $host"; else pass "public network cannot resolve $host"; fi
    done
    ;;

client)
    : "${CLIENT_PRIVATE_KEY:?}" "${SERVER_PUBLIC_KEY:?}" "${ENDPOINT_HOST:?}" "${VIP_NET:?}" "${VIP_DNS:?}"
    : "${EXPECT_TUNNEL:=yes}"   # yes: handshake required, no: none may happen, any: ignore
    : "${EXPECT_ALLOWED:=}"     # comma separated FQDNs that must work
    : "${ALL_FQDNS:?}"
    : "${CLIENT_ADDRESS:=}"
    : "${WG_PORT:=51820}"
    endpoint_ip=$(getent hosts "$ENDPOINT_HOST" | awk '{print $1; exit}')
    [[ -n "$endpoint_ip" ]] || { bad "cannot resolve $ENDPOINT_HOST"; exit 1; }

    keyfile=$(mktemp); printf '%s\n' "$CLIENT_PRIVATE_KEY" >"$keyfile"
    ip link add wg0 type wireguard
    wg set wg0 private-key "$keyfile" peer "$SERVER_PUBLIC_KEY" endpoint "$endpoint_ip:$WG_PORT" \
        allowed-ips "$VIP_NET" persistent-keepalive 1
    rm -f "$keyfile"
    ip address add "${CLIENT_ADDRESS:-10.77.0.200/32}" dev wg0
    ip link set wg0 mtu 1380 up
    ip route add "$VIP_NET" dev wg0

    handshake=0
    for _ in $(seq 1 10); do
        ts=$(wg show wg0 latest-handshakes | awk '{print $2; exit}')
        if [[ -n "${ts:-}" && "$ts" != 0 ]]; then handshake=1; break; fi
        sleep 1
    done
    case "$EXPECT_TUNNEL" in
        yes) [[ $handshake == 1 ]] && pass "handshake completed" || bad "no WireGuard handshake" ;;
        no)  [[ $handshake == 0 ]] && pass "no handshake for unprovisioned peer" || bad "unprovisioned peer completed a handshake" ;;
    esac

    IFS=, read -ra all <<<"$ALL_FQDNS"
    for fqdn in "${all[@]}"; do
        want=0; [[ ",$EXPECT_ALLOWED," == *",$fqdn,"* ]] && want=1
        ip=$(dig +short +time=2 +tries=2 @"$VIP_DNS" "$fqdn" 2>/dev/null | head -1)
        if [[ $handshake == 1 ]]; then
            if [[ -n "$ip" ]]; then pass "DNS $fqdn -> $ip"; else bad "DNS did not resolve $fqdn"; fi
        fi
        if [[ -z "$ip" ]]; then
            # Resolve statically so unprovisioned/denied probes still test the data path.
            case "$fqdn" in
                "${DAV_FQDN:-}") ip=${VIP_DAV:-} ;; "${FLEET_FQDN:-}") ip=${VIP_FLEET:-} ;; "${ACS_FQDN:-}") ip=${VIP_ACS:-} ;;
            esac
        fi
        [[ -n "$ip" ]] || { bad "no address for $fqdn"; continue; }
        body=$(curl -s --max-time 5 --cacert /pki/ca.pem --resolve "$fqdn:443:$ip" "https://$fqdn/" 2>/dev/null) && ok=1 || ok=0
        if [[ $want == 1 ]]; then
            [[ $ok == 1 && "$body" == *-ok ]] && pass "$fqdn reachable and trusted ($body)" || bad "$fqdn should be reachable"
        else
            [[ $ok == 0 ]] && pass "$fqdn denied" || bad "$fqdn reachable without a grant ($body)"
        fi
    done

    if [[ -n "${GATEWAY_WG_ADDRESS:-}" ]]; then
        ip route add "$GATEWAY_WG_ADDRESS/32" dev wg0
        if curl -sk --max-time 3 "https://$GATEWAY_WG_ADDRESS/" >/dev/null 2>&1; then bad "gateway tunnel address answered on 443"; else pass "gateway tunnel address is not a service"; fi
    fi
    if [[ -n "${OTHER_PEER_ADDR:-}" ]]; then
        ip route add "$OTHER_PEER_ADDR/32" dev wg0
        if ping -c1 -W2 "$OTHER_PEER_ADDR" >/dev/null 2>&1; then bad "lateral traffic to another peer was forwarded"; else pass "no lateral traffic between peers"; fi
    fi
    if [[ -n "${VIP_DAV:-}" ]]; then
        if curl -s --max-time 3 "http://$VIP_DAV:80/" >/dev/null 2>&1; then bad "plain HTTP on VIP answered"; else pass "no plain HTTP on service VIP"; fi
    fi
    ;;
*) echo "unknown mode $mode" >&2; exit 2 ;;
esac

exit $fail

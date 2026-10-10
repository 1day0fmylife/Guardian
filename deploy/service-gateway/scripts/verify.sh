#!/usr/bin/env bash
# End-to-end acceptance test for the service gateway reference deployment.
# Builds a throw-away stack (stub upstreams, private CA, own project name),
# provisions two devices with different grants and checks the data path.
# Requires: docker (with compose v2.24+), openssl. Needs NET_ADMIN containers.
set -uo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
state=$(mktemp -d)
project=guardian-gateway-verify
export STATE_DIR=$state COMPOSE_EXTRA_FILE=$here/compose.test.yaml PKI_STUB_NAMES=sunkardav,admiral,sunkarcwmp-acs
failures=0

cleanup() {
    docker compose -p "$project" --env-file "$state/.env" -f "$here/compose.yaml" -f "$here/compose.test.yaml" \
        down -v --remove-orphans >/dev/null 2>&1
    rm -rf "$state"
}
[[ ${KEEP:-0} == 1 ]] || trap cleanup EXIT

section() { echo; echo "== $*"; }
check()   { # description, exit-code
    if [[ $2 == 0 ]]; then echo "PASS $1"; else echo "FAIL $1"; failures=$((failures + 1)); fi
}
tally() { # consume PASS/FAIL lines from a tester run
    local line
    while IFS= read -r line; do
        echo "$line"
        [[ $line == FAIL* ]] && failures=$((failures + 1))
    done
}

chmod 0700 "$state"
sed -e "s|^COMPOSE_PROJECT_NAME=.*|COMPOSE_PROJECT_NAME=$project|" \
    -e 's|^GUARDIAN_PUBLIC_HOST=.*|GUARDIAN_PUBLIC_HOST=guardian.test|' \
    -e 's|^GUARDIAN_MGMT_HOST=.*|GUARDIAN_MGMT_HOST=admin.guardian.test|' \
    -e 's|^GUARDIAN_PUBLIC_URL=.*|GUARDIAN_PUBLIC_URL=https://guardian.test|' \
    -e 's|^UPSTREAM_FLEET=.*|UPSTREAM_FLEET=https://admiral:8443|' \
    -e 's|^UPSTREAM_DAV_TRUST=.*|UPSTREAM_DAV_TRUST=/pki/stub.crt|' \
    -e 's|^UPSTREAM_ACS=.*|UPSTREAM_ACS=https://rogue:8443|' \
    -e 's|^UPSTREAM_ACS_TRUST=.*|UPSTREAM_ACS_TRUST=/pki/stub.crt|' \
    "$here/env.example" >"$state/.env"
chmod 0600 "$state/.env"
set -a; . "$state/.env"; set +a

section "deploy (clean environment)"
"$here/scripts/deploy.sh" "$state" || { echo "FAIL deployment"; exit 1; }
set -a; . "$state/.env"; set +a   # picks up the generated database password
compose=(docker compose -p "$project" --env-file "$state/.env" -f "$here/compose.yaml" -f "$here/compose.test.yaml")
net=${project}_public
image=guardian-gateway:local
server_key=$("${compose[@]}" exec -T wg-gateway wg show wg0 public-key)
gw_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$("${compose[@]}" ps -q wg-gateway)")

run_tester() { # mode, then -e KEY=VAL ...
    local mode=$1; shift
    docker run --rm --network "$net" --cap-add NET_ADMIN -v "$state/pki:/pki:ro" "$@" \
        "$image" /usr/local/bin/gateway-tester.sh "$mode"
}
common_env=(-e "DAV_FQDN=$DAV_FQDN" -e "FLEET_FQDN=$FLEET_FQDN" -e "ACS_FQDN=$ACS_FQDN"
            -e "VIP_NET=$VIP_NET" -e "VIP_DNS=$VIP_DNS" -e "VIP_DAV=$VIP_DAV" -e "VIP_FLEET=$VIP_FLEET" -e "VIP_ACS=$VIP_ACS"
            -e "SERVER_PUBLIC_KEY=$server_key" -e "ENDPOINT_HOST=wg-gateway" -e "WG_PORT=$WG_PORT"
            -e "ALL_FQDNS=$DAV_FQDN,$FLEET_FQDN,$ACS_FQDN" -e "GATEWAY_WG_ADDRESS=${WG_ADDRESS%/*}")

section "gateway hardening"
fwd=$("${compose[@]}" exec -T wg-gateway cat /proc/sys/net/ipv4/ip_forward | tr -d '\r')
check "ip_forward is 0 inside the gateway" "$([[ $fwd == 0 ]]; echo $?)"
rules=$("${compose[@]}" exec -T wg-gateway nft list table inet guardian_gw)
grep -q 'hook input priority filter; policy drop' <<<"$rules"; check "input policy is drop" $?
grep -q 'hook forward priority filter; policy drop' <<<"$rules"; check "forward policy is drop" $?
api_id=$("${compose[@]}" ps -q guardian-api)
api_info=$(docker inspect -f '{{len .HostConfig.CapAdd}} {{.HostConfig.NetworkMode}} {{.HostConfig.Privileged}} {{.HostConfig.ReadonlyRootfs}}' "$api_id")
read -r api_capadd api_netmode api_priv api_ro <<<"$api_info"
[[ $api_capadd == 0 && $api_netmode != host && $api_netmode != container:* && $api_priv == false && $api_ro == true ]]
check "guardian-api: no added caps, no host/shared netns, not privileged, read-only rootfs ($api_info)" $?
api_pid=$(docker inspect -f '{{.State.Pid}}' "$api_id")
api_eff=$(awk '/^CapEff/ {print $2}' "/proc/$api_pid/status" 2>/dev/null)
[[ $api_eff == 0000000000000000 ]]; check "guardian-api effective capabilities are empty (CapEff=${api_eff:-unreadable})" $?

section "public side"
run_tester public-probe -e "TARGET=$gw_ip" -e "ACS_FQDN=$ACS_FQDN" | tally

section "provision devices"
setup=$(run_tester admin-setup \
    -e "API=https://admin.guardian.test:8443" -e "ENROLL=https://guardian.test" \
    -e "WG_ENDPOINT=wg-gateway:$WG_PORT" -e "TUNNEL_CIDR=$TUNNEL_CIDR" -e "WG_ADDRESS=$WG_ADDRESS" \
    -e "SERVER_PUBLIC_KEY=$server_key" -e "VIP_NET=$VIP_NET" -e "VIP_DNS=$VIP_DNS" \
    -e "DAV_FQDN=$DAV_FQDN" -e "FLEET_FQDN=$FLEET_FQDN" -e "ACS_FQDN=$ACS_FQDN")
if ! jq -e '.clients | length == 2' <<<"$setup" >/dev/null 2>&1; then
    echo "FAIL provisioning: $setup"; exit 1
fi
admin_token=$(jq -r .admin_token <<<"$setup")
profile_id=$(jq -r .profile_id <<<"$setup")
api_env=(-e "API=https://admin.guardian.test:8443" -e "ENROLL=https://guardian.test" -e "ADMIN_TOKEN=$admin_token")
client() { jq -r --arg n "$1" --arg f "$2" '.clients[] | select(.name==$n) | .[$f]' <<<"$setup"; }
a_addr=$(client a address); b_addr=$(client b address)
echo "PASS two devices enrolled and granted ($(client a device_id | cut -c1-8)…, $(client b device_id | cut -c1-8)…)"

echo "(waiting for peer reconciliation and ACL sync)"
sleep 8

section "device A: only SunkarDAV (headers, spoofing, lateral)"
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(client a private_key)" -e "CLIENT_ADDRESS=$a_addr" \
    -e "EXPECT_ALLOWED=$DAV_FQDN" -e "OTHER_PEER_ADDR=${b_addr%/*}" -e "CHECK_HEADERS=$DAV_FQDN" \
    -e "SPOOF_ADDR=${b_addr%/*}" -e "SPOOF_FQDN=$FLEET_FQDN" | tally

section "device B: Admiral; ACS upstream fails its pin"
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(client b private_key)" -e "CLIENT_ADDRESS=$b_addr" \
    -e "EXPECT_ALLOWED=$FLEET_FQDN" -e "EXPECT_BADGW=$ACS_FQDN" | tally

section "unprovisioned peer"
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(openssl rand -base64 32)" -e "CLIENT_ADDRESS=10.77.0.200/32" \
    -e "EXPECT_TUNNEL=no" -e "EXPECT_ALLOWED=" | tally

section "scope change is atomic for unchanged services"
hammer=$(docker run -d --network "$net" --cap-add NET_ADMIN -v "$state/pki:/pki:ro" "${common_env[@]}" \
    -e "CLIENT_PRIVATE_KEY=$(client b private_key)" -e "CLIENT_ADDRESS=$b_addr" \
    -e "HAMMER_FQDN=$FLEET_FQDN" -e "HAMMER_SECONDS=22" "$image" /usr/local/bin/gateway-tester.sh hammer)
sleep 6
run_tester admin-regrant "${api_env[@]}" -e "DEVICE_ID=$(client b device_id)" \
    -e "REVOKE_SERVICE=sunkarcwmp-acs" -e "GRANT_SERVICE=sunkardav" >/dev/null
docker wait "$hammer" >/dev/null
docker logs "$hammer" 2>/dev/null | grep -E '^(PASS|FAIL)' | tally
docker rm -f "$hammer" >/dev/null 2>&1
sleep 3
echo "(after the change: B must reach Admiral and SunkarDAV, no longer ACS)"
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(client b private_key)" -e "CLIENT_ADDRESS=$b_addr" \
    -e "EXPECT_ALLOWED=$FLEET_FQDN,$DAV_FQDN" | tally

section "suspended device loses access"
run_tester admin-suspend -e "API=https://admin.guardian.test:8443" -e "ADMIN_TOKEN=$admin_token" -e "DEVICE_ID=$(client a device_id)" >/dev/null
sleep 8
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(client a private_key)" -e "CLIENT_ADDRESS=$a_addr" \
    -e "EXPECT_TUNNEL=any" -e "EXPECT_ALLOWED=" | tally

section "revoked device loses access"
run_tester admin-revoke -e "API=https://admin.guardian.test:8443" -e "ADMIN_TOKEN=$admin_token" -e "DEVICE_ID=$(client b device_id)" >/dev/null
sleep 10
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(client b private_key)" -e "CLIENT_ADDRESS=$b_addr" \
    -e "EXPECT_TUNNEL=any" -e "EXPECT_ALLOWED=" | tally

section "reused tunnel address does not inherit the old peer's access"
new=$(run_tester admin-enroll "${api_env[@]}" -e "PROFILE_ID=$profile_id" -e "GRANT_SERVICE=sunkardav")
c_addr=$(jq -r .address <<<"$new")
if [[ "${c_addr%/*}" == "${b_addr%/*}" ]]; then echo "NOTE new device reuses the revoked device's address ${c_addr%/*}"; else echo "NOTE new device got ${c_addr%/*} (revoked device had ${b_addr%/*}); old key is still tested against both"; fi
sleep 8
echo "(new device C: only SunkarDAV)"
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(jq -r .private_key <<<"$new")" -e "CLIENT_ADDRESS=$c_addr" \
    -e "EXPECT_ALLOWED=$DAV_FQDN" -e "EXPECT_BADGW=" | tally
echo "(revoked device B's key, presenting its old address)"
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(client b private_key)" -e "CLIENT_ADDRESS=$b_addr" \
    -e "EXPECT_TUNNEL=any" -e "EXPECT_ALLOWED=" | tally

section "restart of the ACL sync does not reopen access"
"${compose[@]}" restart guardian-acl >/dev/null 2>&1
sleep 6
run_tester client "${common_env[@]}" -e "CLIENT_PRIVATE_KEY=$(client b private_key)" -e "CLIENT_ADDRESS=$b_addr" \
    -e "EXPECT_TUNNEL=any" -e "EXPECT_ALLOWED=" | tally

section "no secrets in logs"
logs=$("${compose[@]}" logs --no-color 2>&1)
leaks=0
for secret in "$POSTGRES_PASSWORD" "$(cat "$state/wg/private.key")" "$admin_token" \
              "$(client a private_key)" "$(client b private_key)" "$(jq -r .private_key <<<"$new")"; do
    if [[ -n $secret ]] && grep -qF -- "$secret" <<<"$logs"; then leaks=$((leaks + 1)); fi
done
[[ $leaks == 0 ]]; check "no database password, WireGuard key or admin token appears in any container log" $?

echo
if [[ $failures -eq 0 ]]; then echo "ALL CHECKS PASSED"; else echo "$failures CHECK(S) FAILED"; fi
exit $((failures > 0))

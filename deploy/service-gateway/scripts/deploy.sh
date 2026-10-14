#!/usr/bin/env bash
# Clean-environment deployment of the Guardian service gateway reference.
#
#   deploy.sh [state-dir]      default: deploy/service-gateway/state
#
# Prepares secrets, PKI and the WireGuard server key under <state-dir>,
# starts the stack and prints the values needed to create the VPN profile.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
state=${1:-$here/state}
mkdir -p "$state/wg"
chmod 0700 "$state" "$state/wg"
state=$(cd "$state" && pwd)
export STATE_DIR=$state

for tool in docker openssl; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
docker compose version >/dev/null
engine_version=$(docker version --format '{{.Server.Version}}')
engine_version=${engine_version%%-*}
IFS=. read -r engine_major engine_minor _ <<<"$engine_version"
if ! [[ "$engine_major" =~ ^[0-9]+$ && "$engine_minor" =~ ^[0-9]+$ ]] ||
    (( engine_major < 28 || (engine_major == 28 && engine_minor < 1) )); then
    echo "Docker Engine >= 28.1 is required for deterministic gateway interface names (found $engine_version)" >&2
    exit 1
fi

envfile="$state/.env"
if [[ ! -f "$envfile" ]]; then
    (umask 077; cp "$here/env.example" "$envfile")
    echo "created $envfile - review hostnames and TLS settings before exposing the stack"
fi
if grep -q '^POSTGRES_PASSWORD=$' "$envfile"; then
    sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 24)|" "$envfile"
fi
set -a; . "$envfile"; set +a

if [[ ! -f "$state/wg/private.key" ]]; then
    (umask 077; openssl rand -base64 32 >"$state/wg/private.key")
    chmod 0644 "$state/wg/private.key"
fi
"$here/scripts/gen-pki.sh" "$state" "${DAV_FQDN},${FLEET_FQDN},${ACS_FQDN}" "${PKI_STUB_NAMES:-}"

compose=(docker compose --env-file "$envfile" -f "$here/compose.yaml")
[[ -n "${COMPOSE_EXTRA_FILE:-}" ]] && compose+=(-f "$COMPOSE_EXTRA_FILE")
"${compose[@]}" up -d --build --wait --wait-timeout 300

pub=$("${compose[@]}" exec -T wg-gateway wg show wg0 public-key)
cat <<MSG

Service gateway is up.
  WireGuard server public key : $pub
  WireGuard endpoint          : <this host>:${WG_PORT}/udp
  Client address pool         : ${TUNNEL_CIDR} (gateway ${WG_ADDRESS%/*})
  Profile allowed_ips         : ${VIP_NET}
  Profile dns_servers         : ${VIP_DNS}
  Service names               : ${DAV_FQDN} ${FLEET_FQDN} ${ACS_FQDN}
  Private CA to distribute    : $state/pki/ca.pem

Next: bootstrap the first administrator at https://${GUARDIAN_MGMT_HOST}:8443,
create the address pool and VPN profile with the values above, enable the
services in the catalog and grant them to devices.
MSG

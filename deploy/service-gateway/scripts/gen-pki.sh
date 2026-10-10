#!/usr/bin/env bash
# Generates a private CA and a certificate for the service gateway names.
# Usage: gen-pki.sh <state-dir> <fqdn,fqdn,...> [stub-hostname,...]
# Existing material is never overwritten. Replace with your own PKI in
# production; the gateway only needs gateway.crt/.key and upstream-ca.pem.
set -euo pipefail

state=${1:?state dir}
fqdns=${2:?comma separated gateway FQDNs}
stubs=${3:-}
pki="$state/pki"
mkdir -p "$pki"
umask 077

if [[ ! -f "$pki/ca.key" ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$pki/ca.key"
    openssl req -x509 -new -key "$pki/ca.key" -sha256 -days 1825 \
        -subj "/CN=Guardian service gateway CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$pki/ca.pem"
fi

issue() { # name, comma-separated DNS SANs
    local name=$1 sans=$2 san_list="" host
    [[ -f "$pki/$name.crt" ]] && return 0
    IFS=, read -ra hosts <<<"$sans"
    for host in "${hosts[@]}"; do san_list+="DNS:$host,"; done
    openssl ecparam -name prime256v1 -genkey -noout -out "$pki/$name.key"
    openssl req -new -key "$pki/$name.key" -subj "/CN=${hosts[0]}" -out "$pki/$name.csr"
    printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' "${san_list%,}" >"$pki/$name.ext"
    openssl x509 -req -in "$pki/$name.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial \
        -sha256 -days 397 -extfile "$pki/$name.ext" -out "$pki/$name.crt"
    rm -f "$pki/$name.csr" "$pki/$name.ext"
}

issue gateway "$fqdns"
if [[ -n "$stubs" ]]; then
    issue stub "$stubs"
    # Same names, same CA, different key: only a leaf pin can tell them apart.
    issue rogue "$stubs,rogue"
fi
[[ -f "$pki/upstream-ca.pem" ]] || cp "$pki/ca.pem" "$pki/upstream-ca.pem"

# Containers drop DAC_OVERRIDE, so files must be world-readable inside the
# bind mount. The state directory itself stays 0700 on the host.
chmod 0644 "$pki"/*.pem "$pki"/*.crt "$pki"/*.key 2>/dev/null || true
chmod 0600 "$pki/ca.key"
chmod 0700 "$state"
# The pki directory is bind-mounted; containers without DAC_OVERRIDE need to
# traverse it. Access from other host users is blocked by the 0700 state dir.
chmod 0755 "$pki"

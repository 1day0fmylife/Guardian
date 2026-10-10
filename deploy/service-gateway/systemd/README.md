# systemd deployment of the service gateway

For hosts without Docker. The topology and firewall are identical to
`../compose.yaml`; see `docs/service-gateway.md` for the full description.

```
install -d -m 0750 /etc/guardian-gateway
install -m 0755 ../gateway-init.sh /usr/local/sbin/gateway-init.sh
install -m 0644 ../nftables.conf.tmpl ../dnsmasq.conf.tmpl ../Caddyfile.gateway /etc/guardian-gateway/
install -m 0755 guardian guardian-gateway-acl /usr/local/bin/        # built from this repo
cp gateway.env.example /etc/guardian-gateway/gateway.env              # edit
cp guardian.env.example /etc/guardian-gateway/guardian.env            # edit
useradd --system --no-create-home guardian-gw
cp *.service /etc/systemd/system/ && systemctl daemon-reload
systemctl enable --now guardian-api guardian-gateway-network guardian-gateway-dns \
    guardian-gateway-proxy guardian-reconciler guardian-gateway-acl
```

Differences from the Compose reference:

* The reconciler and ACL sync run as the unprivileged `guardian-gw` user with
  only `CAP_NET_ADMIN` (ambient). The API runs with an empty capability set.
* Set `net.ipv4.ip_forward=0`, `net.ipv6.conf.all.forwarding=0` and
  `net.ipv4.conf.all.rp_filter=1` in `/etc/sysctl.d/`; `gateway-init.sh` does
  not touch host-wide sysctls.
* The Compose reference gets the "no packet reaches upstream networks" property
  from the gateway nftables `forward` chain. On a host that also runs other
  services, add host firewall rules for them; the `guardian_gw` table only
  governs traffic that is not otherwise accepted by earlier base chains.

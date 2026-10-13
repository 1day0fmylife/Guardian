# Service gateway image: WireGuard + nftables + dnsmasq tooling plus the two
# Guardian binaries that need network privileges (peer reconciler, ACL sync).
# The Guardian API itself keeps using deploy/server.Dockerfile and stays
# unprivileged.
FROM golang:1.24.13-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/guardian ./cmd/guardian \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/guardian-gateway-acl ./cmd/guardian-gateway-acl

FROM alpine:3.22
RUN apk add --no-cache wireguard-tools nftables dnsmasq gettext iproute2 curl bind-tools jq openssl bash
COPY --from=build /out/guardian /usr/local/bin/guardian
COPY --from=build /out/guardian-gateway-acl /usr/local/bin/guardian-gateway-acl
COPY deploy/service-gateway/gateway-init.sh /usr/local/bin/gateway-init.sh
COPY deploy/service-gateway/nftables.conf.tmpl /etc/guardian-gateway/nftables.conf.tmpl
COPY deploy/service-gateway/cwmp-cr.nft.tmpl /etc/guardian-gateway/cwmp-cr.nft.tmpl
COPY deploy/service-gateway/dnsmasq.conf.tmpl /etc/guardian-gateway/dnsmasq.conf.tmpl
COPY deploy/service-gateway/scripts/tester.sh /usr/local/bin/gateway-tester.sh
RUN chmod 0755 /usr/local/bin/gateway-init.sh /usr/local/bin/gateway-tester.sh

FROM oven/bun:1 AS build
WORKDIR /app
COPY package.json ./
RUN bun install
COPY . .
RUN bun run build

FROM caddy:2.10-alpine
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 80

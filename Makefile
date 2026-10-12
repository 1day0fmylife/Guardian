SHELL := /bin/bash

.PHONY: run web-build build docker-build docker-run test

run:
	@if [ ! -f "$(CURDIR)/.env" ]; then \
		echo "Missing $(CURDIR)/.env (copy .env.example to .env first)"; \
		exit 1; \
	fi
	$(MAKE) web-build
	@set -e; set -a; source "$(CURDIR)/.env"; set +a; \
		listen_addr="$${GUARDIAN_LISTEN_ADDR:-:8080}"; \
		if [[ "$$listen_addr" == :* ]]; then listen_addr="127.0.0.1$$listen_addr"; fi; \
		export GUARDIAN_API_TARGET="http://$$listen_addr"; \
		go run ./cmd/guardian & backend_pid=$$!; \
		(cd web && bun run preview) & frontend_pid=$$!; \
		trap 'kill "$$backend_pid" "$$frontend_pid" 2>/dev/null || true' EXIT; \
		trap 'exit 130' INT; \
		trap 'exit 143' TERM; \
		printf 'Guardian WebUI: http://localhost:4173\n'; \
		wait -n "$$backend_pid" "$$frontend_pid"

web-build:
	cd web && bun install --frozen-lockfile && bun run build

build:
	@mkdir -p bin
	go build -o bin/guardian ./cmd/guardian

docker-build:
	docker compose build

docker-run:
	docker compose up -d

test:
	go test ./...
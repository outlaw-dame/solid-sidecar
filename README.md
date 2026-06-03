# solid-sidecar

Go/Rust sidecar for Community Solid Server. Phase 1 is a Go-only MVP that runs in front of CSS and provides a tested gateway shell: config validation, health/readiness endpoints, request IDs, structured logs, body-size limits, and reverse proxying to CSS.

## Current phase

Implemented: Phase 1 Go sidecar MVP.

Not implemented yet: Phase 2 hardening, Solid-OIDC/DPoP validation, WAC/ACP policy kernels, RDF parsing, Rust services, notification fan-out.

## Project structure

- `cmd/solid-sidecar/`: Go service entrypoint.
- `internal/config/`: config defaults, file loading, env overrides, validation.
- `internal/gateway/`: HTTP server, routing, graceful shutdown shell.
- `internal/proxy/`: CSS reverse proxy and body limits.
- `internal/health/`: liveness and CSS readiness probe.
- `internal/observability/`: structured logging and request IDs.
- `configs/`: example sidecar configs.
- `deploy/`: Docker and Compose development deployment.
- `docs/`: architecture and implementation notes.
- `tests/`: reserved for cross-process integration/security tests.

## Run locally against an existing CSS instance

Start CSS on port 3000, then run:

```sh
go run ./cmd/solid-sidecar -config configs/sidecar.example.yaml
```

Open:

```sh
curl http://localhost:8443/healthz
curl http://localhost:8443/readyz
```

Requests to `http://localhost:8443/` are proxied to CSS at `http://127.0.0.1:3000` by default.

## Run with Docker Compose

```sh
docker compose -f deploy/compose/docker-compose.dev.yml up --build
```

CSS is available through the sidecar at:

```text
http://localhost:8443/
```

CSS is also exposed directly at `http://localhost:3000/` for local debugging only.

## Configuration

Default config lives at `configs/sidecar.example.yaml`. Environment overrides:

- `SOLID_SIDECAR_CONFIG`
- `SOLID_SIDECAR_ADDRESS`
- `SOLID_SIDECAR_BACKEND_URL`
- `SOLID_SIDECAR_BACKEND_HEALTH_PATH`
- `SOLID_SIDECAR_MAX_BODY_BYTES`
- `SOLID_SIDECAR_LOG_LEVEL`

Flags:

```sh
solid-sidecar -config configs/sidecar.example.yaml -listen :8443 -backend-url http://127.0.0.1:3000
```

## Test

```sh
gofmt -w .
go test ./...
go vet ./...
go build ./cmd/solid-sidecar
```

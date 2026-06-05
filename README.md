# solid-sidecar

Go/Rust sidecar for Community Solid Server. The current implementation is a Go sidecar that runs in front of CSS and provides a tested gateway shell: config validation, health/readiness endpoints, request IDs, structured logs, body-size limits, request-target validation, optional Origin enforcement, fixed-window rate limiting, DPoP/OAuth auth preflight, and reverse proxying to CSS. Rust and Go authorization-contract scaffolds now exist in shadow mode for future deterministic policy work. Optional Go authz shadow observation can be enabled, but it remains non-enforcing and does not replace CSS authorization.

## Current phase

Implemented:

- Phase 1 Go sidecar MVP.
- Phase 2 front-door hardening.
- Phase 3 auth preflight for DPoP-shaped Solid requests.
- Phase 4 Rust policy-kernel scaffold in shadow mode.
- Phase 4.1 Go authorization-contract plumbing in shadow mode.
- Phase 4.2 optional Go authz shadow observation wiring, disabled by default.

Not implemented yet: authoritative Solid-OIDC issuer/WebID validation, WAC/ACP/SAI policy evaluation, RDF parsing/canonicalization, Rust runtime integration, policy enforcement, notification fan-out.

## Project structure

- `cmd/solid-sidecar/`: Go service entrypoint.
- `internal/config/`: config defaults, file loading, env overrides, validation.
- `internal/gateway/`: HTTP server, routing, graceful shutdown shell.
- `internal/proxy/`: CSS reverse proxy and body limits.
- `internal/health/`: liveness and CSS readiness probe.
- `internal/observability/`: structured logging and request IDs.
- `internal/safety/`: request validation, security headers, optional Origin policy.
- `internal/ratelimit/`: per-IP fixed-window rate limiter.
- `internal/authn/`: OAuth/DPoP request preflight and replay cache.
- `internal/authz/`: authorization-contract request builder, shadow evaluator, and non-enforcing middleware scaffold.
- `internal/audit/`: redacted rejection audit helpers.
- `contracts/`: JSON schemas for sidecar/kernel interfaces.
- `rust/`: Rust workspace for deterministic internal kernels.
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
- `SOLID_SIDECAR_RATE_LIMIT_ENABLED`
- `SOLID_SIDECAR_RATE_LIMIT_REQUESTS`
- `SOLID_SIDECAR_RATE_LIMIT_WINDOW`
- `SOLID_SIDECAR_ALLOWED_ORIGINS`
- `SOLID_SIDECAR_AUTH_PREFLIGHT_ENABLED`
- `SOLID_SIDECAR_AUTH_VALIDATE_DPOP_SIGNATURE`
- `SOLID_SIDECAR_AUTH_MAX_CLOCK_SKEW`
- `SOLID_SIDECAR_AUTH_REPLAY_WINDOW`
- `SOLID_SIDECAR_AUTH_PUBLIC_BASE_URL`
- `SOLID_SIDECAR_AUTHZ_SHADOW_ENABLED`
- `SOLID_SIDECAR_AUTHZ_PUBLIC_BASE_URL`
- `SOLID_SIDECAR_LOG_LEVEL`

Authz shadow observation can be enabled with:

```yaml
authz:
  shadow_enabled: true
  public_base_url: "https://pod.example"
```

When enabled, the sidecar builds `authz.v1` request contracts and logs shadow decisions, but still passes requests through to CSS.

Flags:

```sh
solid-sidecar -config configs/sidecar.example.yaml -listen :8443 -backend-url http://127.0.0.1:3000
```

## Test

```sh
gofmt -w .
go test ./...
go vet ./...
go test -race ./...
go build ./cmd/solid-sidecar
```

Rust policy-kernel checks, once Rust tooling is available:

```sh
cd rust
cargo fmt --check
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```

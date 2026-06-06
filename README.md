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
- Phase 4.3 shared Go/Rust authorization-contract fixtures.
- Phase 4.4 Go/Rust contract validation hardening.
- Phase 4.5 CI coverage for the Rust policy kernel and shared contract fixtures.
- Phase 4.6 unified verification entrypoint for local and CI checks.
- Phase 4.7 Go/Rust authorization audit-hash parity tests.
- Phase 4.8 privacy-safe authz shadow decision observability.
- Phase 4.9 structured authz shadow deny decisions for invalid contracts.
- Phase 4.10 shared invalid-contract fixtures for Go/Rust deny parity.
- Phase 4.11 expanded contract-valid invalid fixtures for unsupported methods.
- Phase 4.12 sanitized malformed request-ID decision correlation.
- Phase 4.13 explicit authz shadow-deny non-enforcement regression coverage.
- Phase 4.14 hardened authz JSON-schema boundaries and fixture validation coverage.
- Phase 4.15 shared authz fixture manifest for Go/Rust parity tests.
- Phase 4.16 authz fixture manifest coverage audit.
- Phase 4.17 authz fixture manifest schema and filename validation.
- Phase 4.18 Rust authz fixture manifest validation parity.
- Phase 4.19 Rust authz fixture directory coverage audit.
- Phase 4.20 strict authz fixture filename validation aligned with manifest schema.

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
- `internal/authz/`: authorization-contract request builder, codecs, validators, shadow evaluator, deterministic audit hashing, privacy-safe shadow observability, structured invalid-contract decisions, and non-enforcing middleware scaffold.
- `internal/audit/`: redacted rejection audit helpers.
- `contracts/`: JSON schemas and fixtures for sidecar/kernel interfaces.
- `rust/`: Rust workspace for deterministic internal kernels.
- `configs/`: example sidecar configs.
- `deploy/`: Docker and Compose development deployment.
- `docs/`: architecture and implementation notes.
- `scripts/`: local/CI verification scripts.
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

When enabled, the sidecar builds `authz.v1` request contracts and logs privacy-safe shadow decision metadata, including request ID, decision, reason, status hint, cache TTL, resource/policy versions, and deterministic audit hashes. It still passes requests through to CSS even when the shadow evaluator returns a structured deny decision.

## Contract fixtures

Shared Go/Rust authorization fixtures live under `contracts/fixtures/`. The Go sidecar and Rust policy kernel both read `authz_manifest.json` to keep `authz.v1` request, decision, and audit-hash behavior aligned. Go and Rust tests assert that every manifest case produces the expected shadow decision. `contracts/authz_fixture_manifest.schema.json` defines the manifest contract and fixture filename patterns. Invalid fixtures lock structured deny behavior for unsupported schema versions, malformed request IDs, unsupported methods, missing modes, and unsafe resource URIs. Malformed request IDs are replaced in decisions with `invalid-request-<request_hash_prefix>` so the decision remains a valid contract while retaining privacy-safe correlation. Go and Rust tests audit the fixture directory so duplicate manifest file references, invalid fixture names, and orphan `authz_request.*.json` or `authz_decision.*.json` files fail fast. Manifest fixture stems must match `[A-Za-z0-9_-]+`, matching the JSON schema exactly. Rust tests also reject unknown manifest fields and mismatched valid/invalid decision shape. Request and decision schemas explicitly require visible-ASCII request IDs; request schemas also constrain resource/policy URIs to HTTP(S) without fragments, backslashes, or control characters. The Go shadow evaluator mirrors Rust-kernel invalid-contract outcomes while the HTTP middleware remains non-enforcing; shadow deny decisions are observable but do not block CSS. The Go codec rejects unknown JSON fields and trailing JSON; Rust contract types reject unknown fields through Serde.

Flags:

```sh
solid-sidecar -config configs/sidecar.example.yaml -listen :8443 -backend-url http://127.0.0.1:3000
```

## Test

Run all local checks with the same entrypoint used by CI:

```sh
bash scripts/verify.sh all
```

Run only one side of the stack:

```sh
bash scripts/verify.sh go
bash scripts/verify.sh rust
```

The Go path checks formatting, vet, tests, race tests, and the sidecar build. The Rust path checks formatting, workspace tests, and library clippy with warnings denied.

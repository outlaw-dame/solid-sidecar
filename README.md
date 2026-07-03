# solid-sidecar

Go/Rust sidecar for Community Solid Server. The sidecar runs in front of CSS and provides a tested gateway shell for request handling, shadow observation, metadata preparation, fixture contracts, cache metadata, fixture parser scaffolds, artifact metadata, fixture export metadata, fixture release metadata, marker metadata, authn identity scaffolding, and reverse proxying to CSS.

CSS remains the Solid protocol and access-control authority. The sidecar is still non-enforcing; production authorization requires verified identity integration, live policy discovery, real policy parsing/evaluation, comparison against CSS behavior, and enforcement gates.

## Current status

The project has pivoted from metadata phases to production-readiness work. Start with:

- `docs/repository-audit-2026-07-02.md` for the latest reconciliation of recent direct-to-main work against the roadmap.
- `docs/implementation-status.md` for the current done/missing audit.
- `docs/production-implementation-plan.md` for the roadmap.
- `docs/solid-runtime-roadmap-index.md` for the expanded roadmap documentation index.
- `docs/solid-runtime-phase-roadmap.md` for the Go/Rust Solid runtime phase roadmap through Phase 17, including `did:solid`.
- `docs/solid-platform-maturity-phases.md` for post-Phase-17 platform/runtime maturity phases through stable native release.
- `docs/did-solid-method.md` for the initial project-defined `did:solid` method design.
- `docs/compression-compatibility.md` for Gzip/Zstd compatibility rules and implementation phases.
- `docs/runbook-local.md` for local CSS-through-sidecar use.
- `docs/runbook-staging.md` for staging rollout and rollback.
- `docs/authn-identity.md` for authn identity/JWT status.
- `docs/ci.md` for CI and e2e verification.

Recently completed production-readiness work:

- Docker-backed CSS-through-sidecar e2e script.
- Explicit `scripts/verify.sh e2e` target.
- Failure-time CSS and sidecar log dumping for e2e runs.
- Local and staging runbooks.
- Issuer discovery and JWKS cache hardening.
- RS256 JWT verification against JWKS.
- Discovery-backed JWT verification restricted to explicitly allowed issuers.

## Project structure

- `cmd/solid-sidecar/`: Go service entrypoint.
- `internal/config/`: config defaults, file loading, env overrides, validation.
- `internal/gateway/`: HTTP server, routing, graceful shutdown shell, evaluator selection, and metrics snapshot wiring.
- `internal/proxy/`: CSS reverse proxy and body limits.
- `internal/health/`: liveness and CSS readiness probe.
- `internal/observability/`: structured logging and request IDs.
- `internal/safety/`: request validation, security headers, optional Origin policy.
- `internal/ratelimit/`: per-IP fixed-window rate limiter.
- `internal/authn/`: OAuth/DPoP preflight, identity claim validation, issuer discovery, JWKS cache, and JWT verification scaffolding.
- `internal/authz/`: contracts, validators, shadow evaluator, external evaluator wrapper, fixture metadata, artifact metadata, export metadata, release metadata, marker metadata, metrics, audit hashing, and non-enforcing middleware.
- `contracts/`: JSON schemas and shared fixtures.
- `rust/`: Rust workspace for deterministic internal kernels.
- `docs/`: implementation status, architecture, phase notes, `did:solid`, compression compatibility, platform maturity phases, repository audit, and runbooks.
- `scripts/`: local/CI verification scripts.

## Run locally

See `docs/runbook-local.md` for the full local runbook.

Start CSS on port 3000, then run:

```sh
go run ./cmd/solid-sidecar -config configs/sidecar.example.yaml
```

Health checks:

```sh
curl http://localhost:8443/healthz
curl http://localhost:8443/readyz
```

## Docker Compose

```sh
docker compose -f deploy/compose/docker-compose.dev.yml up --build
```

## Test

Run normal Go and Rust checks:

```sh
bash scripts/verify.sh all
```

Run one side of the stack:

```sh
bash scripts/verify.sh go
bash scripts/verify.sh rust
```

Run the Docker-backed CSS-through-sidecar e2e harness explicitly:

```sh
bash scripts/verify.sh e2e
```

The e2e target is intentionally not part of `all` because it requires Docker and starts CSS.

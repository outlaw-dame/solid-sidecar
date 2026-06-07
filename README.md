# solid-sidecar

Go/Rust sidecar for Community Solid Server. The sidecar runs in front of CSS and provides a tested gateway shell for request handling, shadow observation, metadata preparation, fixture contracts, cache metadata, fixture parser scaffolds, artifact metadata, fixture export metadata, fixture release metadata, and reverse proxying to CSS.

CSS remains the Solid protocol and access-control authority. Fixture and artifact phases through Phase 28 are metadata/test scaffolding only and do not change runtime evaluator behavior or enforce access decisions.

## Current status

Phase 28 is complete. The next safe boundary is Phase 29.

Recent completed phases:

- Phase 26: fixture release records with consistency checks.
- Phase 27: fixture release ledgers with deterministic ordering.
- Phase 28: fixture release reviews with deterministic metadata.

Completed phase notes live under `docs/phase-*-completion.md`.

## Project structure

- `cmd/solid-sidecar/`: Go service entrypoint.
- `internal/config/`: config defaults, file loading, env overrides, validation.
- `internal/gateway/`: HTTP server, routing, graceful shutdown shell, evaluator selection, and metrics snapshot wiring.
- `internal/proxy/`: CSS reverse proxy and body limits.
- `internal/health/`: liveness and CSS readiness probe.
- `internal/observability/`: structured logging and request IDs.
- `internal/safety/`: request validation, security headers, optional Origin policy.
- `internal/ratelimit/`: per-IP fixed-window rate limiter.
- `internal/authn/`: OAuth/DPoP request preflight and replay cache.
- `internal/authz/`: contracts, validators, shadow evaluator, external evaluator wrapper, fixture metadata, artifact metadata, export metadata, release metadata, metrics, audit hashing, and non-enforcing middleware.
- `contracts/`: JSON schemas and shared fixtures.
- `rust/`: Rust workspace for deterministic internal kernels.
- `docs/`: architecture and phase notes.
- `scripts/`: local/CI verification scripts.

## Run locally

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

Run all local checks with the same entrypoint used by CI:

```sh
bash scripts/verify.sh all
```

Run only one side of the stack:

```sh
bash scripts/verify.sh go
bash scripts/verify.sh rust
```

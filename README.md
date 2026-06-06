# solid-sidecar

Go/Rust sidecar for Community Solid Server. The current implementation is a Go sidecar that runs in front of CSS and provides a tested gateway shell: config validation, health/readiness endpoints, request IDs, structured logs, body-size limits, request-target validation, optional Origin enforcement, fixed-window rate limiting, DPoP/OAuth auth preflight, optional authorization shadow observation, optional external authz evaluator integration, privacy-safe authz shadow metrics, and reverse proxying to CSS. Phase 4 and Phase 5 are complete. Phase 6 is complete with additional runtime-resilience hardening: the repository now has privacy-safe aggregate shadow observability while CSS remains the Solid protocol and authorization authority.

## Current phase

Phase 6 is complete. The next safe boundary is Phase 7: policy-input preparation without enforcement.

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
- Phase 4.21 Go/Rust authz fixture filename regression tests.
- Phase 4.22 authz middleware evaluator-decision validation before shadow logging.
- Phase 4.23 authz shadow warning logs include request ID correlation.
- Phase 4.24 privacy-safe authz shadow warning reason labels.
- Phase 4.25 centralized authz shadow warning reasons with full warning-path regression coverage.
- Phase 4.26 centralized authz shadow log messages and field names.
- Phase 4.27 authz shadow warning query-string redaction regression coverage.
- Phase 4.28 documented authz shadow logging contract.
- Phase 4.29 Phase 4 completion and Phase 5 handoff documentation.
- Phase 5.1 external CLI authz evaluator scaffold with timeout and output bounds.
- Phase 5.2 external evaluator config validation and tests.
- Phase 5.3 gateway evaluator selection for local vs external CLI shadow mode.
- Phase 5.4 Phase 5 runtime integration documentation and example configuration.
- Phase 5.5 local shadow fallback for external evaluator failures.
- Phase 5.6 bounded backoff wrapper for repeated evaluator failures.
- Phase 5.7 gateway wraps external evaluator mode with backoff.
- Phase 5.8 documentation for external evaluator backoff behavior.
- Phase 5.9 Phase 5 completion and Phase 6 handoff documentation.
- Phase 6.1 privacy-safe authz shadow metrics collector.
- Phase 6.2 middleware metrics recording for decisions, warnings, fallback decisions, and fallback failures.
- Phase 6.3 gateway metrics snapshot wiring for shadow mode.
- Phase 6.4 Phase 6 completion documentation.
- Phase 6.5 configurable external evaluator backoff bounds and backoff-active warning classification.
- Phase 6.6 aggregate-only authz shadow metric dimension contract tests.

Not implemented yet: authoritative Solid-OIDC issuer/WebID validation, WAC/ACP/SAI policy evaluation, RDF parsing/canonicalization, production policy enforcement, decision caching, notification fan-out.

See `docs/phase-4-completion.md`, `docs/phase-5-completion.md`, and `docs/phase-6-completion.md` for completed-phase guarantees, non-goals, and handoff boundaries.

## Project structure

- `cmd/solid-sidecar/`: Go service entrypoint.
- `internal/config/`: config defaults, file loading, env overrides, validation.
- `internal/gateway/`: HTTP server, routing, graceful shutdown shell, authz evaluator selection, and authz metrics snapshot wiring.
- `internal/proxy/`: CSS reverse proxy and body limits.
- `internal/health/`: liveness and CSS readiness probe.
- `internal/observability/`: structured logging and request IDs.
- `internal/safety/`: request validation, security headers, optional Origin policy.
- `internal/ratelimit/`: per-IP fixed-window rate limiter.
- `internal/authn/`: OAuth/DPoP request preflight and replay cache.
- `internal/authz/`: authorization-contract request builder, codecs, validators, local shadow evaluator, optional external CLI evaluator, evaluator backoff wrapper, privacy-safe aggregate metrics, deterministic audit hashing, privacy-safe shadow observability, structured invalid-contract decisions, and non-enforcing middleware scaffold.
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

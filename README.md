# solid-sidecar

Go/Rust sidecar for Community Solid Server. The current implementation is a Go sidecar that runs in front of CSS and provides a tested gateway shell: config validation, health/readiness endpoints, request IDs, structured logs, body-size limits, request-target validation, optional Origin enforcement, fixed-window rate limiting, DPoP/OAuth auth preflight, optional authorization shadow observation, optional external authz evaluator integration, and reverse proxying to CSS. Phase 4 is complete: the repository has a non-enforcing Go/Rust `authz.v1` contract boundary for future deterministic policy work. Phase 5 has begun runtime integration groundwork while CSS remains the Solid protocol and authorization authority.

## Current phase

Phase 5 is active. Current Phase 5 work adds a safe, opt-in external CLI evaluator path for shadow authz observation. It remains non-enforcing and must not block CSS.

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

Not implemented yet: authoritative Solid-OIDC issuer/WebID validation, WAC/ACP/SAI policy evaluation, RDF parsing/canonicalization, production policy enforcement, decision caching, notification fan-out.

See `docs/phase-4-completion.md` for the Phase 4 completion checklist, guarantees, non-goals, and Phase 5 handoff boundary. See `docs/phase-5-runtime-integration.md` for the active Phase 5 runtime integration contract.

## Project structure

- `cmd/solid-sidecar/`: Go service entrypoint.
- `internal/config/`: config defaults, file loading, env overrides, validation.
- `internal/gateway/`: HTTP server, routing, graceful shutdown shell, and authz evaluator selection.
- `internal/proxy/`: CSS reverse proxy and body limits.
- `internal/health/`: liveness and CSS readiness probe.
- `internal/observability/`: structured logging and request IDs.
- `internal/safety/`: request validation, security headers, optional Origin policy.
- `internal/ratelimit/`: per-IP fixed-window rate limiter.
- `internal/authn/`: OAuth/DPoP request preflight and replay cache.
- `internal/authz/`: authorization-contract request builder, codecs, validators, local shadow evaluator, optional external CLI evaluator, deterministic audit hashing, privacy-safe shadow observability, structured invalid-contract decisions, and non-enforcing middleware scaffold.
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
- `SOLID_SIDECAR_AUTHZ_EVALUATOR`
- `SOLID_SIDECAR_AUTHZ_EXTERNAL_COMMAND`
- `SOLID_SIDECAR_AUTHZ_EXTERNAL_ARGS`
- `SOLID_SIDECAR_AUTHZ_EXTERNAL_TIMEOUT`
- `SOLID_SIDECAR_AUTHZ_EXTERNAL_MAX_OUTPUT_BYTES`
- `SOLID_SIDECAR_LOG_LEVEL`

Authz shadow observation can be enabled with:

```yaml
authz:
  shadow_enabled: true
  public_base_url: "https://pod.example"
  evaluator: "local"
```

To opt into the Phase 5 external evaluator seam:

```yaml
authz:
  shadow_enabled: true
  evaluator: "external_cli"
  external_command: "/usr/local/bin/solid-policy-kernel-eval"
  external_args: ""
  external_timeout: "2s"
  external_max_output_bytes: 65536
```

When enabled, the sidecar builds `authz.v1` request contracts and logs privacy-safe shadow decision metadata, including request ID, decision, reason, status hint, cache TTL, resource/policy versions, and deterministic audit hashes. It still passes requests through to CSS even when the shadow evaluator returns a structured deny decision. Evaluator decisions are validated before normal shadow logging; invalid evaluator output is logged as a warning with request ID correlation and one of the stable `error_reason` labels `request_build_failed`, `evaluation_failed`, or `invalid_decision`, never raw error text, and still passes through to CSS. Authz shadow log messages and field names are centralized constants; warning and decision logs use `EscapedPath()` only, so query strings such as tokens or secrets are not emitted. External evaluator calls have a bounded runtime and bounded output, and returned decisions must decode as valid `authz.v1`. If the external evaluator fails or returns invalid output, the sidecar falls back to local shadow evaluation for observability while still passing the request through to CSS.

## Contract fixtures

Shared Go/Rust authorization fixtures live under `contracts/fixtures/`. The Go sidecar and Rust policy kernel both read `authz_manifest.json` to keep `authz.v1` request, decision, and audit-hash behavior aligned. Go and Rust tests assert that every manifest case produces the expected shadow decision. `contracts/authz_fixture_manifest.schema.json` defines the manifest contract and fixture filename patterns. Invalid fixtures lock structured deny behavior for unsupported schema versions, malformed request IDs, unsupported methods, missing modes, and unsafe resource URIs. Malformed request IDs are replaced in decisions with `invalid-request-<request_hash_prefix>` so the decision remains a valid contract while retaining privacy-safe correlation. Go and Rust tests audit the fixture directory so duplicate manifest file references, invalid fixture names, and orphan `authz_request.*.json` or `authz_decision.*.json` files fail fast. Manifest fixture stems must match `[A-Za-z0-9_-]+`, matching the JSON schema exactly, and both Go and Rust include positive/negative regression cases for this filename boundary. Rust tests also reject unknown manifest fields and mismatched valid/invalid decision shape. Request and decision schemas explicitly require visible-ASCII request IDs; request schemas also constrain resource/policy URIs to HTTP(S) without fragments, backslashes, or control characters. The Go shadow evaluator mirrors Rust-kernel invalid-contract outcomes while the HTTP middleware remains non-enforcing; shadow deny decisions are observable but do not block CSS. The Go codec rejects unknown JSON fields and trailing JSON; Rust contract types reject unknown fields through Serde.

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

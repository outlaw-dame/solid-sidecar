# solid-sidecar

Go/Rust sidecar for Community Solid Server (CSS), with Solid HTTP, authentication, authorization-shadow, SDK, storage, runtime, comparison, and transport foundations.

> **Start with [`docs/canonical-status.md`](docs/canonical-status.md).** It is the authoritative reference for implementation state and production readiness. Historical phase reports and release notes do not override it.

## Current release and development state

- Release documentation present: `v0.1.0-alpha`
- Matching published tag/release: not independently confirmed here; the alpha notes say the tag was still to be created
- Current development track: `v0.2.0-beta` preparation
- Current production status: **not production-ready**
- Current authority: CSS
- Default safe mode: CSS proxy/shadow; enforcement and native authority disabled

The immediate target is:

```text
Native or PWA client
  -> Solid HTTP / Solid-OIDC / DPoP
  -> solid-sidecar
  -> CSS remains the compatibility, authorization, and rollback authority
```

The later native-authority target begins only after the CSS-proxy production candidate is complete.

## What exists today

Substantial implementation exists across:

- Go HTTP gateway, CSS reverse proxy, limits, request safety, health/readiness, rate limiting, and observability;
- issuer discovery, JWKS/JWT verification, WebID identity, DPoP validation and key binding;
- live WAC/ACP policy discovery, parsing, evaluation, decision caching, and shadow comparison;
- enforcement and runtime gates that remain disabled or non-authoritative by default;
- storage abstractions and local/S3/SSH-related backends, conditional operations, quotas, tombstones, backup/restore and integrity foundations;
- CSS comparison, HTTP compatibility, container, CORS, compression, and conformance foundations;
- TypeScript and Go SDK foundations;
- TypeScript SDK clients for authentication, DPoP, resources, policies, WebID, RDF, synchronization, and notifications;
- experimental DID, SAI, notification, indexing, multi-tenant, hybrid, and native-runtime work.

Code presence does not imply production readiness. See the component-by-component status and remaining evidence in [`docs/canonical-status.md`](docs/canonical-status.md).

## Critical safety boundaries

- CSS remains authoritative until the CSS-proxy production candidate is approved.
- `did:solid` identity never grants resource access by itself.
- SAI registrations and grants do not bypass WAC/ACP.
- Parse or policy failures never become authoritative allow decisions.
- Native and enforcement modes remain disabled by default.
- Notifications are change hints and require resource revalidation.
- Tokens, DPoP proofs, credentials, private keys, PKCE verifiers, private bodies, and raw policies must not be logged.
- Unsafe client URLs must not become arbitrary outbound requests.
- Automatic retries must not duplicate non-idempotent writes.
- Private resource existence and identifiers must not leak through errors, logs, metrics, caches, notifications, or indexes.

## Current readiness priorities

1. Reconcile all status and readiness claims.
2. Finish complete TypeScript SDK install/typecheck/lint/test/build/package gates.
3. Add secure DPoP signer abstractions for browser and native clients.
4. Verify and harden the Go SDK.
5. Complete formal CSS/direct/proxy/hybrid/native conformance artifacts.
6. Prove browser/PWA and existing Solid JavaScript client compatibility.
7. Complete enforcement-default, isolation, formal security, storage-failure, and consolidated release gates.
8. Build and validate a native reference client and staging soak profile.

See [`docs/native-pwa-production-readiness.md`](docs/native-pwa-production-readiness.md) for execution order and Definition of Done.

## Documentation

### Authoritative current state

- [`docs/canonical-status.md`](docs/canonical-status.md) — canonical component and phase status
- [`docs/native-pwa-production-readiness.md`](docs/native-pwa-production-readiness.md) — native/PWA production-readiness plan

### Historical and supporting material

- [`docs/v1-product-roadmap.md`](docs/v1-product-roadmap.md)
- [`docs/release-notes-v0.1.0-alpha.md`](docs/release-notes-v0.1.0-alpha.md)
- [`docs/repository-audit-2026-07-02.md`](docs/repository-audit-2026-07-02.md)
- [`docs/solid-runtime-roadmap-index.md`](docs/solid-runtime-roadmap-index.md)
- [`docs/solid-runtime-phase-roadmap.md`](docs/solid-runtime-phase-roadmap.md)
- [`docs/solid-platform-maturity-phases.md`](docs/solid-platform-maturity-phases.md)
- [`docs/did-solid-method.md`](docs/did-solid-method.md)
- [`docs/compression-compatibility.md`](docs/compression-compatibility.md)

### Operations

- [`docs/runbook-local.md`](docs/runbook-local.md)
- [`docs/runbook-staging.md`](docs/runbook-staging.md)
- [`docs/authn-identity.md`](docs/authn-identity.md)
- [`docs/ci.md`](docs/ci.md)

## Project structure

- `cmd/solid-sidecar/` — Go service entrypoint
- `internal/config/` — configuration
- `internal/gateway/` — server, routing, evaluator and metrics wiring
- `internal/proxy/` — CSS reverse proxy and body limits
- `internal/authn/` — Solid-OIDC, JWT, WebID, DPoP, DID identity foundations
- `internal/authz/` — policy discovery, parsing/evaluation, cache, comparison and gates
- `internal/runtime/` — storage/runtime/native/notification/index foundations
- `sdk/ts/` — TypeScript SDK
- `sdk/go/` — Go SDK
- `rust/` — deterministic Rust policy/parser kernels
- `contracts/` — schemas and fixtures
- `scripts/` — verification and operations scripts
- `docs/` — architecture, status, roadmap, security and runbooks

## Run locally

Follow [`docs/runbook-local.md`](docs/runbook-local.md). With CSS on port 3000:

```sh
go run ./cmd/solid-sidecar -config configs/sidecar.example.yaml
```

Health checks:

```sh
curl http://localhost:8443/healthz
curl http://localhost:8443/readyz
```

Docker development profile:

```sh
docker compose -f deploy/compose/docker-compose.dev.yml up --build
```

## Verification

```sh
bash scripts/verify.sh all
bash scripts/verify.sh go
bash scripts/verify.sh rust
```

Run the Docker-backed CSS-through-sidecar harness explicitly:

```sh
bash scripts/verify.sh e2e
```

The e2e target is separate because it requires Docker and starts CSS.

## Support and security

- Documentation: `docs/`
- Bugs: GitHub Issues
- Design discussion: GitHub Discussions
- Security reporting: use the repository’s vulnerability-disclosure documentation; the production-readiness roadmap still requires consolidation into a canonical `SECURITY.md` workflow.
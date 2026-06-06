# Solid Sidecar Architecture

This repository implements the operational sidecar that sits in front of Community Solid Server (CSS). Phase 1 established the Go HTTP service shell. Phase 2 hardened the front-door boundary. Phase 3 added authentication preflight for OAuth/DPoP-shaped requests while keeping CSS as the final Solid protocol and authorization authority. Phase 4 is complete and provides a non-enforcing Go/Rust authorization-contract and policy-kernel shadow-mode boundary.

```text
Client
  ↓
solid-sidecar (Go)
  - /healthz
  - /readyz
  - request IDs
  - structured logs
  - body limits
  - request-target validation
  - origin allowlist option
  - fixed-window rate limiting
  - OAuth/DPoP preflight
  - trusted forwarded headers
  - optional authz shadow observation
  - reverse proxy
  ↓
Community Solid Server
```

```text
Phase 4 shadow-only side path

solid-sidecar (Go)
  ↓ authz.v1 contract JSON
solid-policy-kernel (Rust)
  - validates request contract shape
  - hashes request and policy references deterministically
  - returns abstain for valid shadow-mode requests
  - returns input-error decisions for invalid kernel inputs
  ↓ authz.v1 decision JSON
solid-sidecar (Go)
  - validates evaluator decisions
  - emits privacy-safe shadow logs
  - never enforces authz shadow decisions
  ↓
Community Solid Server remains authoritative
```

The Rust side path is a tested contract boundary but is not wired into live request handling yet. When it is introduced, `abstain` must mean “continue to CSS,” and shadow `deny` must remain non-enforcing until a later enforcement phase explicitly changes that behavior behind migration gates.

## Phase 1 responsibility

Phase 1 established:

- config defaults, file loading, environment overrides, and validation;
- an HTTP server with timeout defaults;
- liveness and readiness endpoints;
- backend CSS readiness probing;
- reverse proxying to CSS without semantic rewrites;
- request ID propagation;
- structured JSON logging;
- request body size limits;
- Docker and Compose local development support;
- CI for formatting, vetting, testing, and building.

## Phase 2 responsibility

Phase 2 added front-door hardening:

- encoded dot-segment and backslash path rejection;
- request header control-character rejection;
- hop-by-hop header stripping;
- spoofable forwarded-header stripping and replacement;
- trusted `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` generation;
- optional Origin allowlist enforcement;
- fixed-window per-IP rate limiting;
- redacted rejection audit logs;
- maximum header byte configuration;
- race tests and vulnerability checks in CI.

## Phase 3 responsibility

Phase 3 adds authentication preflight only. It can reject malformed or replayed DPoP-shaped requests before CSS, but it does not decide whether an agent can read or write a Solid resource.

Implemented in Phase 3:

- DPoP authorization shape checks;
- compact DPoP JWT parsing;
- `typ`, `alg`, embedded `jwk`, `htm`, `htu`, `iat`, `jti`, and `ath` validation;
- ES256 and RS256 DPoP proof signature verification;
- access-token hash comparison through `ath`;
- in-memory DPoP replay cache keyed by proof key and `jti`;
- configurable clock skew, replay window, and public base URL for `htu` comparison;
- tests for valid proof acceptance, `ath` mismatch, replay rejection, `htu` query stripping, and middleware rejection behavior.

## Phase 4 responsibility

Phase 4 is complete. It establishes a deterministic, non-enforcing authorization shadow boundary for later policy work.

Implemented in Phase 4:

- `contracts/authz_request.schema.json` for sidecar-to-kernel inputs;
- `contracts/authz_decision.schema.json` for kernel-to-sidecar outputs;
- `contracts/authz_fixture_manifest.schema.json` for shared fixture manifests;
- shared Go/Rust fixture manifest coverage with orphan-file and duplicate-entry checks;
- strict fixture filename validation aligned with schema patterns;
- a Rust workspace under `rust/`;
- a `solid-policy-kernel` crate and CLI evaluation seam;
- typed authorization request, decision, reason-code, audit, and policy-document structures;
- deterministic audit hashes for stable request fields and policy-document references;
- conservative validation for schema version, request ID, method, requested modes, and resource URI shape;
- malformed request-ID sanitization for decision correlation;
- shadow-mode `abstain` behavior for valid requests;
- structured input-error `deny` decisions for invalid kernel input;
- Go shadow middleware that validates evaluator decisions before normal shadow logging;
- explicit non-enforcement tests for shadow deny and invalid evaluator outputs;
- privacy-safe authz shadow logs with centralized messages, centralized field names, stable warning reasons, no raw warning error text, and no query strings in tested warning paths;
- contract tests for abstain behavior, invalid input handling, deterministic hashing, fixture drift, log privacy, and JSON naming.

## Non-goals in Phase 4

Phase 4 does not implement WAC parsing, ACP parsing, SAI policy evaluation, RDF parsing, RDF canonicalization, issuer/WebID policy decisions, Go runtime integration with Rust, decision caching, or production enforcement.

## Boundary rules

1. CSS remains the Solid protocol authority.
2. The sidecar may reject malformed, oversized, rate-limited, disallowed-origin, or invalid DPoP-shaped requests before CSS.
3. The sidecar must not claim to authorize Solid access decisions yet.
4. Request method, path, query, and body are forwarded without semantic rewriting after safety and auth preflight validation.
5. The Rust policy kernel is shadow-only and not wired into live request handling yet.
6. A Rust `abstain` decision means CSS remains the decision-maker.
7. Go authz shadow `deny` and invalid evaluator decisions are observable but non-enforcing.
8. Future issuer/WebID/WAC/ACP/SAI work must be added behind explicit contracts, golden fixtures, observability, and migration gates.

See also `docs/phase-4-completion.md` for the completion checklist and Phase 5 handoff boundary.

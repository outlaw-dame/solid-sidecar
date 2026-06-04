# Solid Sidecar Architecture

This repository implements the operational sidecar that sits in front of Community Solid Server (CSS). Phase 1 established the Go HTTP service shell. Phase 2 hardened the front-door boundary. Phase 3 adds authentication preflight for OAuth/DPoP-shaped requests while keeping CSS as the final Solid protocol and authorization authority.

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
  - reverse proxy
  ↓
Community Solid Server
```

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

## Non-goals in Phase 3

Phase 3 still does not implement authoritative Solid-OIDC issuer discovery, access-token introspection, WebID verification, WAC/ACP evaluation, RDF parsing, Rust kernels, notification fan-out, or production TLS termination. Those belong to later phases after the auth preflight boundary is stable and tested.

## Boundary rules

1. CSS remains the Solid protocol authority.
2. The sidecar may reject malformed, oversized, rate-limited, disallowed-origin, or invalid DPoP-shaped requests before CSS.
3. The sidecar must not claim to authorize Solid access decisions yet.
4. Request method, path, query, and body are forwarded without semantic rewriting after safety and auth preflight validation.
5. Later issuer/WebID/policy work must be added behind explicit contracts and tests.

# Solid Sidecar Architecture

This repository implements the operational sidecar that sits in front of Community Solid Server (CSS). Phase 1 intentionally keeps the sidecar small: it starts a Go HTTP service, exposes liveness/readiness endpoints, validates configuration, reverse-proxies Solid requests to CSS, applies basic request limits, and preserves a clean boundary for later auth, policy, RDF, and Rust-kernel work.

```text
Client
  ↓
solid-sidecar (Go)
  - /healthz
  - /readyz
  - request IDs
  - structured logs
  - body limits
  - reverse proxy
  ↓
Community Solid Server
```

## Phase 1 responsibility

Phase 1 establishes the service shell only:

- config defaults, file loading, environment overrides, and validation;
- an HTTP server with safe timeout defaults;
- liveness and readiness endpoints;
- backend CSS readiness probing;
- reverse proxying to CSS without semantic rewrites;
- request ID propagation;
- structured JSON logging;
- request body size limits;
- Docker and Compose local development support;
- CI for formatting, vetting, testing, and building.

## Non-goals in Phase 1

Phase 1 does not implement Solid-OIDC, DPoP validation, WAC/ACP evaluation, RDF parsing, Rust kernels, notification fan-out, or production TLS termination. Those belong to later phases after the HTTP boundary is stable and tested.

## Boundary rules

1. CSS remains the Solid protocol authority in Phase 1.
2. The sidecar may reject malformed or oversized requests before CSS.
3. The sidecar must not claim to authorize Solid access decisions yet.
4. Request method, path, query, and body must be forwarded without semantic rewriting.
5. Later auth/policy work must be added behind explicit contracts and tests.

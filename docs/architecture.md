# Solid Sidecar Architecture

This repository implements the operational sidecar that sits in front of Community Solid Server (CSS). Phase 1 established the Go HTTP service shell. Phase 2 hardens that boundary without adding Solid-OIDC, DPoP, WAC/ACP, RDF, or Rust-kernel behavior yet.

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

Phase 2 adds front-door hardening:

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

## Non-goals in Phase 2

Phase 2 still does not implement Solid-OIDC, DPoP validation, WAC/ACP evaluation, RDF parsing, Rust kernels, notification fan-out, or production TLS termination. Those belong to later phases after the HTTP boundary is stable and tested.

## Boundary rules

1. CSS remains the Solid protocol authority.
2. The sidecar may reject malformed, oversized, rate-limited, or disallowed-origin requests before CSS.
3. The sidecar must not claim to authorize Solid access decisions yet.
4. Request method, path, query, and body are forwarded without semantic rewriting after safety validation.
5. Later auth/policy work must be added behind explicit contracts and tests.

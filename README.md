# solid-sidecar

Go/Rust sidecar for Community Solid Server. The sidecar runs in front of CSS and provides a comprehensive Solid protocol implementation with shadow observation, production gateway capabilities, and advanced authorization infrastructure.

**Current Version: v0.1.0-alpha** | **Phase: Post-Phase 40 - Versioned Product Development**

CSS remains the Solid protocol and access-control authority. The sidecar provides comprehensive Solid protocol support with configurable enforcement capabilities. The platform has evolved significantly beyond the original "CSS-front-door plus shadow shell" baseline.

## Version Badge

```markdown
[![Version](https://img.shields.io/badge/version-v0.1.0--alpha-blue.svg)](https://github.com/outlaw-dame/solid-sidecar/releases)
```

## Current Implementation Overview

The project has advanced through **40 phases** of development with substantial implementation across all major Solid protocol areas:

### Core Infrastructure ✅
- Go sidecar entrypoint with comprehensive configuration
- Production-grade HTTP server with graceful shutdown
- Reverse proxying to CSS with advanced request handling
- Request IDs, structured logging, and distributed tracing
- Request body limits and security headers
- Per-IP fixed-window rate limiting
- Comprehensive health and readiness endpoints

### Authentication & Identity ✅
- DPoP-shaped preflight checks with key binding
- Identity claim parsing with validation
- Issuer discovery with bounded HTTP fetches
- Issuer metadata cache with TTL controls
- JWKS fetch and cache with copy-safe records
- RS256 JWT signature verification
- WebID URI validation with fragment preservation
- AgentIdentity with WebID, DID, issuer, client ID binding
- DID resolver with SSRF protection (disabled by default)

### Authorization ✅
- Authorization shadow contracts and middleware
- Local shadow evaluator for WAC/ACP
- External evaluator boundary with timeouts
- Aggregate authz metrics and audit hashing
- Policy metadata, fixture, artifact infrastructure
- Enforcement gate scaffolding with canary controls
- Policy decision caching with smart invalidation

### Solid Protocol Support ✅
- Full Solid Protocol 2023 specification support
- Web Access Control (WAC) parser and evaluator
- Access Control Policy (ACP) parser and evaluator
- Solid Application Interoperability (SAI) service implementation
- Content negotiation for RDF formats (Turtle, JSON-LD, N-Triples)
- CORS compatibility with preflight support
- Container and resource metadata handling

### Storage & Runtime ✅
- Storage abstraction layer with multiple backends
- Local filesystem backend
- S3 backend with AWS SDK v2 integration
- SSH/SFTP backend with transport security
- Runtime modes: css_proxy, hybrid, native
- Fixture distribution infrastructure

### Observability & Monitoring ✅
- OpenTelemetry integration (traces, metrics, logs)
- Distributed tracing across all components
- Structured logging with privacy-safe redaction
- Custom metrics for authorization decisions
- Production dashboards and alert rules
- Comprehensive health check suite

### Advanced Features ✅
- Load testing infrastructure (Phase 17)
- Migration tooling and CSS comparison harness
- Multi-tenant platform scaffolding
- Notification system with live updates
- Indexing and query layer foundations
- Compression support (Gzip, Zstd)

## Documentation & Roadmap

**Start here for current status:**

- `docs/v1-product-roadmap.md` - **v1.0 Product Roadmap** (Versioned development transition)
- `docs/release-notes-v0.1.0-alpha.md` - **v0.1.0 Alpha Release Notes**
- `docs/repository-audit-2026-07-02.md` - **REQUIRED READING** Latest reconciliation of implementation vs documentation
- `docs/implementation-status.md` - Current done/missing audit (being updated in Phase 40)
- `docs/production-implementation-plan.md` - Production readiness roadmap
- `docs/solid-runtime-roadmap-index.md` - Expanded roadmap documentation index
- `docs/solid-runtime-phase-roadmap.md` - Go/Rust Solid runtime roadmap through Phase 17
- `docs/solid-platform-maturity-phases.md` - Platform maturity phases 18-31
- `docs/phase-39-continued-platform-maturity.md` - Continued maturity phases 39.1-39.5
- `docs/phase-40-status-reconciliation.md` - **COMPLETED** Status reconciliation and cleanup (97% complete)

**Protocol Specifications:**

- `docs/did-solid-method.md` - Project-defined `did:solid` method design
- `docs/compression-compatibility.md` - Gzip/Zstd compatibility rules

**Operations:**

- `docs/runbook-local.md` - Local CSS-through-sidecar runbook
- `docs/runbook-staging.md` - Staging rollout and rollback procedures
- `docs/authn-identity.md` - Authentication identity/JWT status
- `docs/ci.md` - CI and e2e verification

## ⚠️ Important Notes

**Production Readiness:** This is an **ALPHA release** (v0.1.0-alpha). While substantial implementation exists, several areas require additional hardening and verification before production use:

- **Authorization Enforcement:** Enforcement gates exist but run in shadow mode; enforcement requires comparison thresholds and canary controls
- **Native Runtime Mode:** Native mode is gated and requires explicit readiness verification and comparison evidence
- **SAI Implementation:** SAI Application Interoperability service exists; **SAI Authorization Enforcement is explicitly deferred**
- **Transport Security:** S3/SSH transports are implemented with security hardening; additional verification pending
- **Known Limitations:** See `docs/release-notes-v0.1.0-alpha.md` for complete list

**Safety Boundary:** CSS remains the compatibility oracle. Every enforcement or native-runtime replacement must have rollback controls. `did:solid` does not grant access by itself.

**Alpha Status:** This release is suitable for development and testing but NOT for production deployment.

## Recent Production-Readiness Work

- Docker-backed CSS-through-sidecar e2e script
- Explicit `scripts/verify.sh e2e` target
- Failure-time CSS and sidecar log dumping for e2e runs
- Local and staging runbooks
- Issuer discovery and JWKS cache hardening
- RS256 JWT verification against JWKS
- Discovery-backed JWT verification restricted to explicitly allowed issuers
- Enhanced Observability with OpenTelemetry integration
- Comprehensive health endpoints and debugging tools
- Solid protocol test suite integration
- Community feedback incorporation mechanisms

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

---

## Version History

| Version | Date | Status | Notes |
|---------|------|--------|-------|
| v0.1.0-alpha | 2026-07-07 | Current | First public alpha release (Phase 40 transition) |

**Note**: This is the first versioned release. Previous development versions were tracked via phase completions (Phases 1-40).

---

## Release Information

- **Latest Release Notes**: See `docs/release-notes-v0.1.0-alpha.md`
- **Product Roadmap**: See `docs/v1-product-roadmap.md`
- **Phase Status**: See `docs/phase-40-status-reconciliation.md` (97% complete)

---

## Support

- **Documentation**: Comprehensive documentation in `docs/` directory
- **Issues**: Report on GitHub Issues
- **Discussions**: GitHub Discussions for non-bug questions
- **Security**: See `docs/VULNERABILITY-DISCLOSURE.md`

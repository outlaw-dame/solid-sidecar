# Implementation Status

This document summarizes what is currently implemented in `solid-sidecar` and what still blocks production authorization use.

## Current usable shape

The sidecar is usable as a hardened CSS front-door and shadow-observation shell.

Implemented:

- Go sidecar entrypoint;
- configuration loading, defaults, env overrides, and validation;
- health and readiness endpoints;
- reverse proxying to CSS;
- request IDs and structured logs;
- request body limits;
- request-target validation;
- trusted forwarded-header handling;
- optional Origin policy;
- fixed-window rate limiting;
- DPoP-shaped preflight checks;
- authorization shadow contracts;
- local shadow evaluator;
- optional external evaluator boundary with timeout, output limit, fallback, and backoff;
- aggregate authz shadow metrics;
- policy metadata, fixture, artifact, export, release, and marker scaffolding;
- Docker-backed CSS-through-sidecar e2e harness;
- CI and e2e GitHub Actions workflow files;
- local and staging runbooks.

## Authn identity work completed

Implemented:

- bounded identity claim parsing;
- issuer URI validation;
- WebID URI validation with fragment preservation;
- allowed issuer checks;
- expected audience checks;
- expiration and issued-at validation;
- bounded client identifier validation;
- issuer discovery with bounded HTTP fetches;
- issuer metadata cache;
- JWKS fetch with bounded HTTP fetches;
- JWKS cache with copy-safe records;
- JSON content-type checks;
- same-origin JWKS checks;
- compact JWT parsing;
- RS256-only JWT signature verification;
- RSA JWK key selection by `kid`;
- RSA JWK safety checks;
- discovery-backed JWT verification restricted to explicitly allowed issuers;
- cooldown-protected JWKS refresh;
- one verification retry after JWT signature/key failure;
- DPoP confirmation / key-binding checks;
- WebID profile ownership proof via HTTP fetch and validation;
- authn middleware behind explicit config;
- trusted identity injection into authz request-builder.

Still missing before authn can feed authorization decisions:

- e2e tests with real signed tokens from a test issuer.

## Runtime authorization work completed

Implemented:

- non-enforcing authz request contracts;
- contract validation and codec boundaries;
- deterministic audit hashes;
- structured invalid-contract shadow decisions;
- privacy-safe decision and warning logs;
- warning reason labels;
- local and external evaluator boundary;
- fallback behavior when external evaluator fails;
- backoff behavior for repeated external evaluator failures;
- aggregate metrics without identifiers;
- HTTP policy source loader with URI validation, scheme checking, and content-type filtering;
- live policy source loading with retry logic for server errors and rate limiting;
- body size limits for policy documents;
- content type detection from response body;
- AncestorPolicyWalk for container-level policy discovery and loading;
- live policy source discovery middleware on the request path with configurable exponential backoff, DoS protection, Link header support, and derived URI tails;
- live policy source loading/cache integration in shadow mode with CachedPolicyLoader, PolicyCacheStore interface, cache metrics, and automatic cache refresh;
- RDF parser boundary with parser registry, content type detection, security hardening, input validation, and timeout protection.

Still missing before authorization can enforce:
- RDF parser/canonicalization boundary;
- ACP parser;
- SAI parser or explicit decision to defer SAI;
- real WAC/ACP/SAI evaluator;
- CSS behavior comparison harness;
- enforcement mode config;
- decision cache for enforcement;
- canary and rollback controls.

## Test and operations work completed

Implemented:

- `scripts/verify.sh go`;
- `scripts/verify.sh rust`;
- explicit `scripts/verify.sh e2e`;
- Docker Compose e2e script;
- e2e failure log dumping;
- CI workflow;
- e2e workflow;
- CI runbook;
- local runbook;
- staging runbook.

## Phase 2 work completed

Implemented:

- method/media-type validation for write requests;
- GET, HEAD, OPTIONS, PUT, POST, PATCH, and DELETE compatibility fixtures;
- storage-root discovery handling and validation;
- container slash and redirect behavior middleware;
- description-resource link handling and parsing;
- CORS behavior tests for browser Solid apps;
- direct CSS vs sidecar pass-through comparison for common request shapes;
- compatibility matrix for CSS behavior that is intentionally proxied unchanged.

**Phase 2 is complete.**

Still missing:

- observed green GitHub Actions runs through the connector;
- stable branch-protection policy;
- staging deployment evidence;
- staged traffic comparison results;
- operational metrics endpoint or OpenTelemetry export;
- alerting guidance.

## Phase 6 work completed

Implemented:

- WAC parser with RDFParser interface integration for seamless use with existing RDF infrastructure;
- WAC-specific data model: WACRule, WACPolicy, WACParseResult structures;
- Security hardening: input size limits (inherits 10MB max from RDF), timeouts (30s default), URI validation with fragment support for WebIDs;
- Rule count limits (100 default) for DoS protection;
- Shadow mode: non-enforcing parser that returns parsed rules without affecting authorization decisions;
- Automatic access mode parsing from various WAC URI formats (full URIs, namespace prefixes, angle-bracket wrapped);
- WebID fragment URI support for agent identifiers;
- Comprehensive test suite with 15+ tests covering parsing, validation, timeout, and error handling;
- Interface compliance verification with RDFParser.

**Phase 6 is complete.**

## Current priority order

Continue in this order:

1. WAC evaluator in shadow mode.
2. CSS behavior comparison harness.
3. Enforcement gate design.
4. ACP parser.

## Current safety boundary

The sidecar must remain CSS-authoritative and non-enforcing until all of the following are true:

- CI and e2e checks are visible and reliable;
- authn middleware accepts only verified and key-bound identity;
- live policy discovery and loading/cache works in shadow mode without request-path hangs;
- RDF parser boundary with content type detection, parser registry, security hardening, input validation, and timeout protection;
- WAC parser in shadow mode for parsing WAC policies;
- WAC/ACP parser/evaluator output can be compared against CSS behavior;
- mismatch rate is measured;
- enforcement gates and emergency bypass exist;
- logs are privacy-reviewed.

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
- discovery-backed JWT verification restricted to explicitly allowed issuers.

Still missing before authn can feed authorization decisions:

- key refresh after signature/key-selection miss;
- DPoP confirmation / key-binding checks;
- WebID profile ownership proof;
- middleware integration behind explicit config;
- authz request-builder integration;
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
- aggregate metrics without identifiers.

Still missing before authorization can enforce:

- live policy source discovery on the request path;
- live policy source loading/cache integration on the request path;
- RDF parser/canonicalization boundary;
- WAC parser;
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

Still missing:

- observed green GitHub Actions runs through the connector;
- stable branch-protection policy;
- staging deployment evidence;
- staged traffic comparison results;
- operational metrics endpoint or OpenTelemetry export;
- alerting guidance.

## Current priority order

Continue in this order:

1. Key refresh on JWT signature/key-selection miss.
2. DPoP confirmation/key-binding checks.
3. Authn middleware integration behind explicit config.
4. Pass verified identity into authz request construction.
5. Live policy source discovery on the request path in shadow mode.
6. Live policy source loading/cache integration in shadow mode.
7. RDF parser boundary selection and hardening.
8. WAC parser in shadow mode.
9. WAC evaluator in shadow mode.
10. CSS behavior comparison harness.
11. Enforcement gate design.

## Current safety boundary

The sidecar must remain CSS-authoritative and non-enforcing until all of the following are true:

- CI and e2e checks are visible and reliable;
- authn middleware accepts only verified and key-bound identity;
- live policy discovery/loading works in shadow mode without request-path hangs;
- WAC/ACP parser/evaluator output can be compared against CSS behavior;
- mismatch rate is measured;
- enforcement gates and emergency bypass exist;
- logs are privacy-reviewed.

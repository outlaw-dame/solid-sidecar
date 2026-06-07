# Production Implementation Plan

This document is the implementation reset point for `solid-sidecar`.

The sidecar is already useful as a hardened front-door reverse proxy and shadow-observation shell, but it is not yet a production Solid authorization sidecar. CSS remains authoritative for Solid protocol behavior and authorization until the enforcement phases below are complete.

## Current state

Implemented and usable now:

- Go HTTP sidecar entrypoint;
- config loading, defaults, env overrides, and validation;
- health and readiness endpoints;
- CSS reverse proxying;
- request IDs and structured logs;
- request body limits;
- request-target validation;
- trusted forwarded-header handling;
- optional Origin allowlist;
- fixed-window rate limiting;
- DPoP-shaped auth preflight;
- non-enforcing authorization shadow contracts;
- optional external evaluator boundary with timeout, output limit, fallback, and backoff;
- fixture contracts and deterministic metadata scaffolding.

Not production-ready yet:

- no authoritative Solid-OIDC issuer/WebID validation;
- no WebID ownership / agent identity resolution beyond request-shape preflight;
- no WAC parser;
- no ACP parser;
- no SAI parser;
- no RDF canonicalization or graph normalization;
- no real policy evaluation;
- no policy decision cache used on the request path;
- no enforce mode;
- no staged rollout gates for enforcement;
- no production end-to-end CSS compatibility suite;
- CI status is not currently visible through the connector used during implementation.

## Guiding rule

Stop adding metadata-only phases until the sidecar can be exercised end-to-end against CSS and the live request path is proven.

Every new phase must either:

1. make the sidecar more usable in local/staging deployments;
2. move real authorization parsing/evaluation closer to enforcement; or
3. reduce production risk through tests, observability, or rollout controls.

## Milestone A: make the sidecar runnable and testable end-to-end

Goal: prove a developer can run CSS behind the sidecar and exercise real HTTP behavior.

### A1. Local end-to-end harness

Implement:

- `tests/e2e/` or `internal/e2e/` harness that starts:
  - CSS container;
  - sidecar container/process;
  - test client;
- basic proxy tests:
  - GET public resource through sidecar;
  - HEAD through sidecar;
  - OPTIONS through sidecar;
  - POST/PUT/PATCH/DELETE pass-through semantics where CSS permits;
  - request body limit rejection;
  - malformed path rejection;
  - readiness failure when CSS is unavailable;
  - graceful shutdown behavior.

Acceptance criteria:

- `bash scripts/verify.sh go` includes a fast non-network unit path.
- A separate e2e command exists for container-backed CSS tests.
- E2E tests do not require secrets.
- E2E tests document exact CSS image/tag used.

### A2. CI visibility repair

Implement:

- workflow checks that surface clearly on the latest commit;
- separate jobs for Go unit, Go race, Rust unit, integration/e2e, vulnerability scan;
- artifact upload for logs when e2e fails;
- fail-fast formatting checks.

Acceptance criteria:

- latest commit exposes check status through GitHub UI/API;
- failed e2e logs identify sidecar logs and CSS logs separately;
- no stale run confusion.

### A3. Operational runbook

Implement:

- `docs/runbook-local.md`;
- `docs/runbook-staging.md`;
- explicit commands for:
  - running CSS directly;
  - running CSS behind sidecar;
  - enabling authz shadow mode;
  - enabling external evaluator mode;
  - reading logs;
  - rolling back to CSS-direct mode.

Acceptance criteria:

- a developer can follow docs from clean checkout to working CSS-through-sidecar setup.

## Milestone B: fix authn from shape-checking to identity confidence

Goal: move from DPoP-shaped preflight to real identity inputs that policy evaluation can trust.

### B1. Solid-OIDC discovery and issuer validation

Implement:

- issuer discovery with bounded HTTP client;
- JWKS retrieval and caching;
- issuer allowlist / trust policy;
- ID token validation where applicable;
- audience/client validation rules;
- strict clock skew bounds;
- structured errors without token leakage.

Acceptance criteria:

- tests for valid issuer, unknown issuer, stale JWKS, key rotation, expired token, wrong audience;
- no raw token material in logs.

### B2. WebID and agent identity extraction

Implement:

- canonical agent identity extraction from validated token claims;
- WebID URI validation;
- optional client identifier binding;
- explicit unauthenticated/public request representation;
- privacy-safe log fields.

Acceptance criteria:

- authz request builder receives trusted agent/client fields only from validated authn layer;
- spoofed headers cannot inject identity.

### B3. DPoP production hardening

Implement:

- persistent or distributed replay cache option for multi-instance deployments;
- proof key thumbprint calculation;
- stricter htm/htu canonicalization tests;
- replay-cache memory bounds and eviction metrics.

Acceptance criteria:

- replay protection survives realistic request bursts;
- failure logs remain privacy-safe.

## Milestone C: policy input discovery on the live request path

Goal: collect the real policy documents needed for evaluation without enforcing yet.

### C1. Resource-to-policy discovery

Implement:

- discover candidate policy sources for a request resource;
- support explicit config, link headers, Solid conventions, and cached metadata;
- reject unsafe policy source URIs;
- bounded fetch size and timeout;
- content-type validation.

Acceptance criteria:

- unit tests for discovery sources;
- e2e tests with CSS resources that expose policy hints;
- no SSRF footguns.

### C2. Policy source loading and cache integration

Implement:

- live source loader wiring;
- cache store integration;
- stale-while-revalidate behavior in shadow mode only;
- cache metrics and bounded retries/backoff.

Acceptance criteria:

- request path does not hang on slow policy sources;
- policy loading failures produce shadow abstain/fallback, not enforcement.

### C3. Shadow request enrichment

Implement:

- attach real discovered policy documents to authz request contracts;
- attach resource metadata from live request path;
- keep deterministic audit hashes stable.

Acceptance criteria:

- shadow logs show aggregate policy input status without leaking content;
- contract fixtures include live-discovered examples.

## Milestone D: real policy parsing in shadow mode

Goal: parse policies into internal facts without deciding access yet.

### D1. RDF parsing and canonicalization boundary

Implement:

- choose parser/runtime boundary:
  - Rust parser kernel preferred for deterministic/security-critical parsing;
  - Go wrapper handles I/O, limits, and error classification;
- parse Turtle/JSON-LD/N-Triples as needed;
- canonical graph representation;
- parser input size limits;
- parser timeout;
- parser error taxonomy.

Acceptance criteria:

- parser never panics on malformed RDF;
- fuzz/property tests for parser boundary where feasible;
- malformed input is classified and logged safely.

### D2. WAC parser in shadow mode

Implement:

- parse WAC authorization resources into typed facts;
- map agents, groups, public access, accessTo/default scopes, and modes;
- no enforcement yet;
- golden fixtures from realistic WAC examples.

Acceptance criteria:

- WAC fixtures include allow, deny-by-absence, public read, group, default/container cases;
- parser output is deterministic.

### D3. ACP parser in shadow mode

Implement:

- parse ACP policy resources into typed facts;
- map matcher/policy/access-control relationships;
- no enforcement yet;
- golden fixtures for resource and member policies.

Acceptance criteria:

- ACP fixtures include grant, deny, member, agent/group/public cases;
- parser output is deterministic.

### D4. SAI parser in shadow mode

Implement:

- parse SAI-relevant policy metadata only after exact target semantics are documented;
- keep SAI behind explicit feature flag if semantics remain unstable;
- no enforcement yet.

Acceptance criteria:

- documented semantics and fixtures before parser is considered complete.

## Milestone E: real policy evaluation in shadow mode

Goal: compute decisions in parallel with CSS but never block requests yet.

### E1. Evaluation model

Implement:

- common evaluator interface over parsed facts;
- decision reasons:
  - explicit allow;
  - explicit deny where supported;
  - no matching policy;
  - parse error;
  - identity unavailable;
  - policy unavailable;
- decision confidence classification.

Acceptance criteria:

- no ambiguous decision is treated as enforceable;
- all errors degrade to abstain or non-enforcing deny in shadow mode.

### E2. WAC evaluator

Implement:

- mode matching;
- agent/public/group matching;
- resource vs container/default matching;
- method-to-mode mapping;
- deterministic explanations.

Acceptance criteria:

- golden tests align with expected WAC semantics;
- shadow decisions are visible and privacy-safe.

### E3. ACP evaluator

Implement:

- matcher evaluation;
- grant/deny behavior according to documented ACP semantics;
- member policy handling;
- deterministic explanations.

Acceptance criteria:

- golden tests align with expected ACP semantics;
- shadow decisions are visible and privacy-safe.

### E4. Compare with CSS behavior

Implement:

- e2e tests comparing sidecar shadow outcome with CSS actual status;
- mismatch metrics;
- mismatch sampling logs without leaking resource content.

Acceptance criteria:

- mismatch rate is measurable before enforcement is considered.

## Milestone F: enforcement gates and production rollout

Goal: move from shadow mode to safe enforcement only after evidence supports it.

### F1. Enforcement mode config

Implement:

- `authz.mode: shadow | enforce_dry_run | enforce_canary | enforce`;
- denylist/allowlist for resources and tenants;
- per-method enforcement gates;
- emergency bypass flag;
- startup validation that prevents accidental enforce mode.

Acceptance criteria:

- enforcement cannot be enabled by a single ambiguous env var;
- bypass returns to CSS-authoritative behavior immediately.

### F2. Decision cache for enforcement

Implement:

- cache key includes agent, client, method/mode, resource, policy version, parser version, evaluator version;
- TTL bounded by policy freshness;
- explicit invalidation on policy changes;
- stale decision handling rules.

Acceptance criteria:

- stale allow cannot survive policy changes beyond configured bounds;
- cache poisoning tests exist.

### F3. Enforcement canary

Implement:

- enforce only on selected safe resources/methods;
- compare with CSS response;
- auto-disable on mismatch/error thresholds;
- clear operator logs and metrics.

Acceptance criteria:

- canary can be enabled and disabled without redeploying;
- all enforcement decisions are explainable and auditable.

### F4. Full enforcement readiness review

Required evidence before full enforcement:

- CI green and visible;
- e2e tests passing;
- parser fuzz/property tests passing where available;
- shadow mismatch rate below agreed threshold;
- rollback tested;
- logs privacy-reviewed;
- performance under expected load measured;
- threat model updated.

## Milestone G: production hardening

Goal: make the sidecar safe to operate continuously.

Implement:

- structured metrics endpoint or OpenTelemetry export;
- alerting guidance;
- pprof/debug endpoint policy;
- memory and goroutine leak tests;
- bounded queues and caches;
- multi-instance replay/cache story;
- config schema documentation;
- migration notes for old configs;
- versioned contract compatibility matrix.

Acceptance criteria:

- operator can tell whether sidecar is healthy, degraded, shadow-only, or enforcing;
- all failure modes are documented with safe fallback behavior.

## Immediate next implementation order

Do these next, in this exact order:

1. Local CSS-through-sidecar e2e harness.
2. CI visibility repair.
3. Local and staging runbooks.
4. Authn identity confidence: issuer/JWKS/WebID validation.
5. Live policy source discovery and loading in shadow mode.
6. RDF parser boundary selection and parser hardening.
7. WAC parser shadow mode.
8. WAC evaluator shadow mode.
9. CSS behavior comparison harness.
10. Enforcement gate design and implementation.

## Stop conditions

Pause implementation and reassess if any of these occur:

- CI cannot be made visible and reliable;
- e2e tests are flaky for CSS-through-sidecar pass-through;
- parser behavior is nondeterministic;
- policy mismatch rate cannot be measured;
- logs leak tokens, WebIDs where not intended, resource contents, or policy contents;
- enforcement requires guessing policy semantics.

## Definition of usable

### Usable for local development

- CSS runs behind sidecar;
- health/readiness pass;
- basic CRUD traffic reaches CSS unchanged;
- DPoP preflight can be enabled;
- shadow mode can be enabled;
- logs and metrics are understandable.

### Usable for staging

- all local criteria;
- e2e suite passes in CI;
- shadow policy source loading works;
- authn identity extraction is trustworthy;
- no request-path hangs under slow policy sources.

### Usable for production enforcement

- all staging criteria;
- real WAC/ACP parsing and evaluation;
- mismatch metrics against CSS;
- enforcement gates;
- emergency bypass;
- decision cache safety;
- rollback runbook;
- threat model and privacy review.

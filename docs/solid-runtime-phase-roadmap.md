# Solid Runtime Phase Roadmap

This roadmap is the implementation spine for turning `solid-sidecar` from a hardened Community Solid Server front door into a modern Go/Rust Solid runtime path.

The current safety boundary still applies: CSS remains the Solid protocol and authorization authority until identity, policy discovery, policy parsing, evaluation, comparison, enforcement gates, and rollback controls are complete. The roadmap below must not be interpreted as permission to enforce access-control decisions early.

## Scope

This roadmap is only for Solid work in this repository:

- Go HTTP gateway/runtime services;
- Rust deterministic kernels for security-sensitive parsing/evaluation;
- CSS compatibility and migration support;
- Solid-OIDC, WebID, WAC, ACP, SAI decisions where explicitly documented;
- `did:solid` as a project-defined DID method extension that complements, but does not bypass, WebID/Solid-OIDC/Solid authorization semantics.

Do not blend in local-first P2P, ActivityPub, ATProto, or other project roadmaps unless a future document explicitly adds them to this repository's Solid scope.

## Guiding principles

1. **CSS compatibility first.** CSS remains the behavior oracle until the sidecar/runtime has measurable compatibility evidence.
2. **Shadow before enforcement.** Every authz parser/evaluator phase starts in shadow mode.
3. **Rust owns deterministic kernels.** Parsing, canonicalization, and policy evaluation should move into Rust where determinism, fuzzing, and panic-safety matter most.
4. **Go owns the gateway.** HTTP, configuration, middleware, observability, cache coordination, and CSS reverse-proxy compatibility remain Go responsibilities.
5. **No identity shortcut.** `did:solid` must not grant access by itself. It can strengthen controller identity and portability only after explicit binding to WebID/Solid-OIDC and policy inputs.
6. **Compatibility-preserving performance.** Compression, caching, indexing, and protocol optimizations must be negotiated and reversible, never forced in ways that break existing Solid clients.

## Phase 1: Authn trust completion

Goal: move from JWT verification scaffolding to request-path trusted identity.

Implement:

- DPoP proof validation for protected requests;
- `cnf` confirmation/key-binding checks between token and proof key;
- strict `htm` and `htu` canonicalization tests;
- bounded replay cache with memory limits;
- optional distributed replay-cache interface for multi-instance deployments;
- authn middleware behind explicit config;
- trusted identity injection into authz request construction;
- WebID profile ownership proof where required by the chosen Solid-OIDC interpretation;
- privacy-safe identity failure logs;
- e2e tests with signed tokens from a controlled test issuer.

Acceptance criteria:

- unbound tokens never become trusted identities;
- spoofed headers cannot inject identity;
- authz request construction receives identity only from verified authn middleware;
- DPoP replay attempts are rejected;
- token, proof, and private key material never appear in logs.

## Phase 2: Solid HTTP request compliance hardening

Goal: make the gateway Solid-aware without changing CSS behavior unexpectedly.

Implement:

- method/media-type validation for write requests;
- `GET`, `HEAD`, `OPTIONS`, `PUT`, `POST`, `PATCH`, and `DELETE` compatibility fixtures;
- container slash and redirect behavior tests;
- storage-root discovery handling;
- description-resource link handling;
- CORS behavior tests for browser Solid apps;
- direct CSS vs sidecar pass-through comparison for common request shapes;
- compatibility matrix for CSS behavior that is intentionally proxied unchanged.

Acceptance criteria:

- sidecar pass-through does not change CSS response status, headers, or body for supported baseline cases;
- malformed or unsafe request targets remain rejected before proxying;
- Solid clients can still interact through the sidecar without custom client behavior.

## Phase 3: Live policy discovery in shadow mode

Goal: discover real authorization inputs on the request path without enforcing.

Implement:

- WAC `acl` link discovery;
- ACP access-control-resource discovery;
- description-resource discovery;
- ancestor/container policy walk;
- explicit config overrides for test/staging policy sources;
- safe URI validation for discovered policy sources;
- bounded policy fetch size;
- policy fetch timeout and retry budget;
- content-type validation;
- cache metadata for discovered policy sources;
- stale-while-revalidate behavior in shadow mode only.

Acceptance criteria:

- slow or unavailable policy sources cannot hang the request path;
- policy loading failures produce shadow abstain/fallback only;
- no policy document body is logged;
- shadow contracts include policy input status without leaking policy content.

## Phase 4: Rust RDF parser and canonical graph boundary

Goal: define the hardened RDF boundary for policy parsing.

Implement in Rust:

- parser kernel crate API;
- Turtle parsing boundary;
- N-Triples parsing boundary;
- JSON-LD support decision: supported through a hardened boundary or explicitly deferred;
- canonical internal graph representation;
- deterministic term ordering;
- parser input size limits;
- parser timeout/cancellation integration;
- malformed-input error taxonomy;
- panic-safe FFI/process boundary;
- fuzz/property tests where feasible.

Implement in Go:

- bounded I/O into the Rust parser boundary;
- parser invocation timeout;
- structured error mapping;
- metrics for parse success/failure/timeout;
- privacy-safe parse diagnostics.

Acceptance criteria:

- malformed RDF never panics the runtime;
- parser output is deterministic for equivalent input;
- parser limits are covered by tests;
- parse failures cannot become enforceable authorization decisions.

## Phase 5: WAC parser and evaluator in shadow mode

Goal: compute real WAC shadow decisions.

Implement:

- parse `acl:Authorization` resources into typed facts;
- map `acl:agent`, `acl:agentClass`, and `acl:agentGroup`;
- map `acl:accessTo` and `acl:default`;
- map read, write, append, and control modes;
- container/default inheritance handling;
- method-to-mode mapping;
- deterministic WAC explanations;
- `WAC-Allow` shadow output where applicable;
- golden WAC fixtures for allow, deny-by-absence, public read, group access, default/container access, append-only, and control cases.

Acceptance criteria:

- parser output is deterministic;
- evaluator reasons are privacy-safe;
- every WAC decision remains shadow-only;
- CSS behavior comparison records mismatches.

## Phase 6: ACP parser and evaluator in shadow mode

Goal: support ACP without treating it as WAC.

Implement:

- Access Control Resource parser;
- Access Control parser;
- Policy parser;
- Matcher parser;
- access grant graph model;
- member policy handling;
- grant/deny behavior according to documented ACP semantics;
- deterministic ACP explanations;
- golden ACP fixtures for resource policy, member policy, agent, group, public, grant, deny, and mixed cases.

Acceptance criteria:

- ACP parser/evaluator remains behind explicit feature/config gates until semantics are fully documented in this repo;
- ACP decisions are measured against CSS behavior where CSS exposes comparable behavior;
- no ACP ambiguity becomes enforceable.

## Phase 7: SAI decision and parser boundary

Goal: decide whether SAI belongs in the first enforcement path.

Implement:

- `docs/sai-support-decision.md` describing target semantics, interoperability expectations, and deferral risks;
- feature flag for any SAI parsing work;
- parser only after semantics are documented;
- fixtures only from explicit, reviewed examples.

Acceptance criteria:

- SAI is either explicitly deferred or scoped to documented metadata parsing;
- SAI does not block WAC/ACP enforcement readiness unless chosen as a required project goal.

## Phase 8: `did:solid` method design

Goal: define a Solid-native DID method extension without breaking WebID/Solid-OIDC compatibility.

Implement documentation first:

- `docs/did-solid-method.md`;
- method syntax;
- DID document shape;
- DID-to-WebID binding;
- WebID-to-DID binding;
- verification method requirements;
- service endpoint vocabulary;
- DID resolution process;
- DID update/rotation process;
- DID deactivation process;
- privacy and correlation risks;
- security considerations;
- interoperability limits while `did:solid` is project-defined.

Initial method shape:

```text
did:solid:<method-specific-id>
```

Required DID document service endpoints:

- Solid storage endpoint;
- WebID endpoint;
- OIDC issuer endpoint;
- optional notification endpoint;
- optional profile/documentation endpoint.

Rules:

- WebID remains the primary Solid agent identifier.
- `did:solid` is an additional controller identity.
- DID ownership alone must never grant resource access.
- Authorization remains WAC/ACP/SAI policy-driven.
- Access can use DID-derived information only when policy semantics explicitly support it.

Acceptance criteria:

- method design doc exists before resolver implementation;
- resolver test vectors exist before runtime integration;
- DID/WebID binding is bidirectional and verifiable;
- key rotation cannot silently change the WebID controller without evidence.

## Phase 9: `did:solid` resolver and identity binding

Goal: implement DID resolution and bind it into trusted identity without increasing access by default.

Implement:

- Go DID resolver package;
- strict parser for `did:solid` identifiers;
- DID document fetch/validation boundary;
- allowed resolver/source policy;
- DID document cache with bounded TTL;
- verification method validation;
- WebID service endpoint validation;
- WebID backlink validation;
- key rotation validation;
- resolver test vectors;
- privacy-safe resolver errors.

Acceptance criteria:

- invalid DID documents fail closed for DID binding;
- DID resolver failures degrade to WebID-only behavior when WebID authn is otherwise valid;
- DID binding does not alter authz decisions unless a later policy phase explicitly supports DID references.

## Phase 10: Canonical internal agent model

Goal: unify WebID, Solid-OIDC issuer, client, DPoP key, and optional DID identity.

Implement:

```text
AgentIdentity {
  webid: URI
  did: optional DID
  issuer: URI
  client_id: URI/string
  token_binding_key_thumbprint: string
  assurance_level: enum
  verification_source: enum
}
```

Implement:

- explicit assurance levels;
- public/unauthenticated identity representation;
- privacy-safe identity hashing for metrics;
- audit-safe identity summaries;
- compatibility tests proving identity cannot be injected through headers.

Acceptance criteria:

- all authz request builders use the canonical identity model;
- WebID-only clients remain supported;
- DID-enhanced clients receive no extra authorization unless policy explicitly grants it.

## Phase 11: CSS behavior comparison harness

Goal: measure divergence before enforcement.

Implement:

- direct CSS vs sidecar-shadow matrix;
- WAC fixture comparison;
- ACP fixture comparison;
- policy discovery comparison;
- identity-path comparison;
- mismatch classifications:
  - parser mismatch;
  - authn mismatch;
  - policy discovery mismatch;
  - inheritance mismatch;
  - CSS behavior ambiguity;
  - sidecar bug;
- privacy-safe sampled mismatch logs;
- mismatch metrics endpoint/export.

Acceptance criteria:

- mismatch rate is visible before enforcement;
- mismatch examples are actionable without leaking tokens, resource bodies, or policy bodies;
- enforcement remains blocked until mismatch thresholds are defined and met.

## Phase 12: Compression negotiation compatibility

Goal: add Gzip and Zstd support without breaking Solid clients, CSS compatibility, ranges, ETags, signatures, or streaming behavior.

Implement according to `docs/compression-compatibility.md`:

- response compression negotiation by `Accept-Encoding`;
- request decompression only where safe and explicitly enabled;
- Gzip support first;
- Zstd support behind explicit feature/config gates;
- `Vary: Accept-Encoding` handling;
- ETag/Content-Length/Content-Encoding correctness;
- range request safety;
- no compression for already-compressed or small responses;
- no compression for sensitive/error bodies unless reviewed;
- CSS direct vs sidecar comparison fixtures.

Acceptance criteria:

- clients that do not advertise compression receive identity-compatible responses;
- Gzip is negotiated only when accepted;
- Zstd is negotiated only when accepted and enabled;
- `HEAD` metadata remains correct;
- range requests are not corrupted by dynamic compression;
- cached variants do not cross-contaminate identity/gzip/zstd responses.

## Phase 13: Decision cache and invalidation

Goal: make authorization fast enough for a modern scalable Solid runtime.

Implement:

- cache key including agent, optional DID, client, method/mode, resource, policy hash/version, parser version, evaluator version;
- bounded TTL;
- stale decision rules;
- policy-change invalidation;
- negative-cache safety;
- cache poisoning tests;
- multi-instance cache interface;
- metrics for hit/miss/stale/invalidated decisions.

Acceptance criteria:

- stale allow cannot survive beyond configured freshness;
- policy changes invalidate related decisions;
- cache poisoning attempts fail;
- cache behavior is observable without leaking identities or resources.

## Phase 14: Enforcement gates and canary

Goal: move from shadow to enforce only with rollback and evidence.

Implement:

```yaml
authz:
  mode: shadow | enforce_dry_run | enforce_canary | enforce
```

Implement:

- resource allowlist;
- storage/tenant allowlist;
- method allowlist;
- emergency bypass;
- mismatch auto-disable;
- startup guardrails preventing accidental enforcement;
- canary metrics;
- operator runbook updates;
- enforcement audit logs with privacy review.

Acceptance criteria:

- enforcement cannot be enabled by a single ambiguous environment variable;
- bypass returns immediately to CSS-authoritative behavior;
- canary can be disabled without redeploying;
- all denies are explainable and auditable.

## Phase 15: Native Go/Rust Solid runtime path

Goal: evolve from CSS sidecar to scalable Solid implementation while preserving compatibility.

Implement in layers:

1. gateway compatibility layer;
2. storage abstraction;
3. metadata/index layer;
4. RDF graph/index layer;
5. policy engine;
6. notification/live-update layer;
7. multi-storage/multi-tenant runtime;
8. CSS migration and compatibility mode.

Acceptance criteria:

- CSS comparison remains available during migration;
- storage backend can be swapped without changing protocol behavior;
- policy engine behavior remains fixture-backed;
- no native runtime path skips compatibility tests.

## Phase 16: Notifications, live updates, and indexing

Goal: support modern application performance without leaking private data.

Implement:

- Solid notification support plan;
- resource-change event stream;
- container metadata index;
- WebID-scoped index access;
- policy-aware index filtering;
- no private resource body indexing unless explicitly allowed;
- observability for event lag and dropped events.

Acceptance criteria:

- clients can observe resource changes through documented mechanisms;
- index results respect authorization;
- private content does not leak through metadata indexes.

## Phase 17: Production hardening

Goal: operate continuously.

Implement:

- OpenTelemetry metrics/traces;
- structured health states:
  - healthy;
  - degraded;
  - shadow-only;
  - enforcing;
  - bypassed;
- pprof/debug endpoint policy;
- memory and goroutine leak tests;
- Rust panic/abort behavior policy;
- load tests;
- replay/cache multi-instance story;
- config schema docs;
- threat model;
- privacy review;
- release checklist.

Acceptance criteria:

- operators can tell whether the runtime is healthy, degraded, shadow-only, enforcing, or bypassed;
- every high-risk feature has a rollback path;
- logs are privacy-reviewed;
- threat model covers authn, authz, compression, caching, DID, and policy parsing.

## Immediate next implementation order

Proceed in this order:

1. DPoP confirmation and key-binding.
2. Authn middleware and trusted identity injection.
3. Live WAC/ACP policy discovery.
4. Rust RDF parser boundary.
5. WAC parser and evaluator.
6. CSS behavior comparison harness.
7. Compression compatibility scaffolding for Gzip first, Zstd gated.
8. `did:solid` method design doc.
9. `did:solid` resolver test vectors.
10. Enforcement gate design.

## Stop conditions

Pause implementation and reassess if any of these occur:

- identity verification requires trusting unverified claims;
- DPoP binding cannot be proven;
- policy discovery can hang the request path;
- parser output is nondeterministic;
- CSS mismatch rate cannot be measured;
- compression changes client-visible semantics unexpectedly;
- Zstd support breaks older clients or intermediaries;
- DID binding creates authorization shortcuts;
- logs leak tokens, DPoP proofs, WebIDs where not intended, request bodies, resource bodies, or policy bodies.

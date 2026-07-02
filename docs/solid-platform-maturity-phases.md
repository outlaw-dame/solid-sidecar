# Solid Platform Maturity Phases

This document extends `docs/solid-runtime-phase-roadmap.md` after Phase 17.

Phases 1–17 make the sidecar safe, observable, comparable against CSS, and ready for carefully gated enforcement. Phases 18–31 move the project toward a mature Go/Rust Solid platform: a native runtime, production storage, durable operations, migration tooling, extension points, and stable release discipline.

The same safety boundary still applies until explicitly retired by documented evidence: CSS remains the compatibility oracle, every enforcement or native-runtime replacement must have rollback controls, and `did:solid` must not become an authorization shortcut.

## Phase 18: Production storage engine

Goal: define and implement the storage substrate that can eventually support a native Go/Rust Solid runtime without hard-coding CSS assumptions.

Implement:

- storage interface package for resource reads, writes, metadata, delete, copy/move where supported, and conditional operations;
- content-addressed blob option for immutable payload storage;
- path-addressed resource mapping for Solid URL compatibility;
- metadata store for resource type, content type, size, digest, modified time, owner/storage root, auxiliary links, and policy references;
- transaction boundary for resource body + metadata updates;
- storage backend adapters, starting with local filesystem/test backend and one production-grade object/blob backend;
- quota accounting by storage root and tenant;
- tombstone/deletion marker semantics for safe cache/index invalidation;
- migration-safe storage layout versioning;
- backup/restore hooks;
- integrity scanner that verifies metadata/body consistency.

Acceptance criteria:

- storage adapters pass the same behavioral contract tests;
- metadata and body updates cannot diverge silently;
- resource URLs remain stable across backend changes;
- storage backend failures produce deterministic errors;
- quota checks cannot be bypassed by alternate write paths;
- no private resource body is logged or exposed through metadata errors.

Implementation notes:

- Keep the storage interface small and Solid-oriented.
- Do not expose backend-specific behavior to authz or HTTP layers.
- Treat backend adapters as replaceable plugins only after the core interface is stable.
- Add conformance fixtures before adding a second production backend.

## Phase 19: Native authorization authority

Goal: graduate from shadow evaluation and CSS comparison to first-class authorization decisions made by the Go/Rust runtime.

Implement:

- explicit authority-mode configuration separate from sidecar proxy mode;
- enforcement-ready WAC evaluator path;
- enforcement-ready ACP evaluator path if ACP is selected for production support;
- SAI enforcement decision according to Phase 7 outcome;
- policy discovery cache with invalidation tied to storage writes and auxiliary resource updates;
- deny/allow reason taxonomy safe for audit and client-facing diagnostics;
- strict fail-closed/fail-open policy by endpoint class;
- operator-visible decision trace IDs;
- emergency CSS-authoritative fallback where CSS is still present;
- regression suite proving previous shadow fixtures behave the same under enforcement.

Acceptance criteria:

- enforcement mode cannot be enabled without passing comparison thresholds;
- every allow/deny decision has a structured reason code;
- policy parser errors cannot turn into accidental allows;
- policy changes invalidate affected decisions before stale allows can persist;
- CSS fallback/bypass is documented and tested;
- native authz does not grant access from `did:solid` binding alone.

Implementation notes:

- Keep the policy engine deterministic.
- Prefer explicit abstain/indeterminate states over guessed decisions.
- Make enforcement mode impossible to enable accidentally through one loose environment variable.

## Phase 20: Solid conformance and interoperability suite

Goal: make compatibility measurable across protocol features, clients, and deployment modes.

Implement:

- full HTTP method matrix for Solid resources and containers;
- storage description, auxiliary resource, and link-header tests;
- WebID/Solid-OIDC/DPoP interoperability fixtures;
- WAC and ACP fixture suites;
- CSS direct vs sidecar vs native-runtime comparison harness;
- known Solid client compatibility matrix;
- browser CORS/preflight compatibility tests;
- content negotiation tests for RDF and non-RDF resources;
- conditional request tests for ETag, Last-Modified, If-Match, If-None-Match;
- range and compression compatibility tests;
- public conformance report artifact.

Acceptance criteria:

- every supported protocol feature has a test fixture;
- every intentional CSS divergence is documented;
- client compatibility failures include reproduction steps;
- conformance reports are generated in CI;
- native runtime cannot ship a stable release without a conformance report.

Implementation notes:

- Treat this as a product artifact, not only a test folder.
- Store expected failures explicitly with reasons and target resolution phases.
- Keep fixtures reusable by Go, Rust, and e2e harnesses.

## Phase 21: Multi-tenant/operator platform

Goal: support real operators running many storage roots, tenants, or hosted Solid deployments without cross-tenant leakage.

Implement:

- tenant model and tenant-scoped configuration;
- storage root registry;
- per-tenant issuer/trust policy;
- per-tenant authz mode and compression mode;
- quota/rate-limit policy by tenant and storage root;
- tenant-scoped metrics labels with privacy-safe cardinality controls;
- operator API for tenant lifecycle operations;
- tenant-safe config reload;
- tenant isolation tests;
- audit log partitioning and retention policy;
- admin runbook for onboarding/offboarding tenants.

Acceptance criteria:

- one tenant cannot read or infer another tenant's private resources;
- tenant config changes cannot affect unrelated tenants;
- metrics avoid raw WebIDs/resource URLs as labels;
- operator APIs require explicit admin authentication/authorization;
- tenant deletion/export behavior is documented and tested.

Implementation notes:

- Start with static tenant config before dynamic operator APIs.
- Keep single-tenant deployments simple; multi-tenant support must not complicate local development.

## Phase 22: Federated identity and trust expansion

Goal: harden identity trust across issuers, WebIDs, clients, key rotation, and `did:solid` while preserving Solid compatibility.

Implement:

- issuer trust policy model with allowlists, pinning, and discovery constraints;
- WebID profile cache with bounded TTL and invalidation;
- WebID ownership verification rules tied to Solid-OIDC behavior;
- client identifier trust/registration policy;
- DPoP key rotation and replay-cache multi-instance story;
- `did:solid` resolver trust policy from Phase 9;
- DID/WebID equivalence proof model;
- key rotation audit events;
- identity assurance levels wired into audit only at first;
- negative tests for issuer spoofing, WebID substitution, and DID confusion.

Acceptance criteria:

- identity state is reproducible from trusted inputs;
- issuer changes cannot silently rebind a WebID;
- DID binding cannot override WebID/OIDC validation;
- key rotation has bounded cache behavior;
- identity failures are privacy-safe and actionable.

Implementation notes:

- Do not let assurance levels change authorization until a later policy phase explicitly defines that semantics.
- Keep trust-policy parsing separate from token parsing.

## Phase 23: High-performance indexing and query layer

Goal: provide fast container listings, metadata lookups, and optional query features without leaking private resource content.

Implement:

- resource metadata index;
- container membership index;
- auxiliary resource index;
- policy-aware index filtering;
- storage-root scoped query API;
- index invalidation on writes/deletes/policy changes;
- background reindex job with checkpointing;
- index consistency verifier;
- optional RDF term index for metadata and policy documents;
- optional semantic/search plugin interface with strict privacy gates;
- benchmark suite for listing, lookup, and invalidation.

Acceptance criteria:

- index results never reveal unauthorized private resource existence unless Solid semantics explicitly allow it;
- index updates are atomic enough to avoid stale private listings;
- rebuilding an index does not require taking the runtime offline;
- query APIs are explicitly scoped and authorization-checked;
- semantic/search plugins are disabled by default and cannot ingest private bodies without explicit policy.

Implementation notes:

- Separate metadata indexing from body indexing.
- Keep indexes derived and rebuildable; source of truth remains storage + policy state.

## Phase 24: Notifications and realtime productionization

Goal: move from notification planning to durable, backpressure-aware realtime behavior.

Implement:

- Solid notifications support according to selected protocol profile;
- durable event log for resource changes;
- subscription registry with authentication and authorization checks;
- per-subscriber cursor/resume support;
- backpressure handling and drop policy;
- fanout workers with bounded queues;
- notification filtering by resource, container, storage root, and policy visibility;
- delivery metrics for lag, drops, retries, and disconnects;
- replay/resync endpoint where appropriate;
- e2e tests with reconnect and missed-event scenarios.

Acceptance criteria:

- private resource changes are not broadcast to unauthorized subscribers;
- clients can resume after disconnect without missing authorized events within retention limits;
- slow subscribers cannot exhaust runtime memory;
- event retention and deletion semantics are documented;
- notification behavior degrades safely under load.

Implementation notes:

- Start with durable local/test event log, then add production backend.
- Treat notifications as derived signals; authorization still applies at delivery time.

## Phase 25: Migration tooling

Goal: allow operators and users to move from CSS-backed deployments to the native runtime with verification and rollback.

Implement:

- CSS inventory scanner;
- export reader for resources, containers, auxiliary resources, ACL/ACP/metadata, and storage descriptions;
- import writer into native storage engine;
- dry-run migration mode;
- checksum and metadata verification report;
- policy comparison report;
- identity/issuer mapping checks;
- resumable migration jobs;
- rollback plan where CSS remains available;
- backup creation before destructive steps;
- operator runbook for staged migrations.

Acceptance criteria:

- migration can run in dry-run mode without modifying target storage;
- every imported resource has body and metadata verification;
- policy resources are preserved and re-evaluated;
- failed migrations are resumable or safely restartable;
- rollback path is documented before production migration is allowed.

Implementation notes:

- Migration tooling should be CLI-first before operator API integration.
- Never delete source CSS data as part of the first migration implementation.

## Phase 26: Security audit and formal hardening

Goal: subject the runtime to adversarial review, fuzzing, invariant testing, and external audit readiness.

Implement:

- complete threat model for authn, authz, storage, policy parsing, compression, DID, indexing, notifications, and migration;
- fuzz targets for RDF parsers, WAC/ACP parsers, DID parser, HTTP target parser, compression negotiation, and config parser;
- property tests for authorization invariants;
- dependency audit and supply-chain policy;
- secret scanning and log-redaction tests;
- parser sandboxing or process isolation decision;
- external audit checklist;
- vulnerability disclosure policy;
- security regression suite;
- release-blocking severity taxonomy.

Acceptance criteria:

- high-risk parsers have fuzz coverage;
- known authz invariants are encoded as tests;
- secrets/tokens/proofs/private bodies are redacted in logs;
- audit findings become tracked work items;
- stable release is blocked on unresolved critical/high security issues.

Implementation notes:

- Treat fuzz fixtures as long-lived assets.
- Run expensive fuzzing outside normal quick CI, but keep smoke fuzz tests in CI.

## Phase 27: SDK/client compatibility layer

Goal: make the runtime easy and safe for Solid app developers to use without relying on undocumented behavior.

Implement:

- Go SDK for operator/runtime APIs where appropriate;
- Rust SDK crates for parser/policy/storage integration where appropriate;
- TypeScript client examples for Solid app compatibility;
- documented HTTP examples for authn, resource CRUD, policy resources, notifications, and migration checks;
- compatibility recipes for common Solid JS clients;
- local dev fixtures and sample pods;
- SDK versioning policy;
- integration tests that exercise examples against the sidecar/native runtime.

Acceptance criteria:

- examples run against local dev environment;
- SDKs do not expose unsafe internal APIs as stable surfaces;
- client compatibility docs distinguish standard Solid behavior from project extensions;
- `did:solid` examples are optional and never required for baseline Solid use.

Implementation notes:

- Keep SDKs thin until runtime APIs stabilize.
- Prefer documented HTTP behavior over magic client helpers.

## Phase 28: Clustered deployment

Goal: support horizontally scaled deployments with consistent authn, authz, cache, storage, and notification behavior.

Implement:

- distributed replay cache for DPoP proofs;
- distributed decision cache or cache-invalidation bus;
- shared storage backend configuration;
- leader election or coordination for background jobs;
- notification fanout across instances;
- rolling upgrade compatibility rules;
- config distribution/reload model;
- readiness states that account for cluster dependencies;
- chaos/failure tests for partial outages;
- cluster runbook.

Acceptance criteria:

- DPoP replay cannot succeed by switching instances;
- policy changes invalidate decisions across the cluster;
- background jobs are not duplicated unsafely;
- rolling upgrades preserve protocol behavior;
- cluster degradation is visible to operators.

Implementation notes:

- Keep single-node mode first-class.
- Avoid requiring a heavyweight cluster dependency for local development.

## Phase 29: Policy and compliance framework

Goal: support operator/user obligations around retention, audit, data residency, consent-sensitive behavior, and administrative access.

Implement:

- audit retention policy config;
- data residency documentation and tenant/storage placement hooks;
- administrative access policy and audit trail;
- export/delete request workflow primitives;
- legal-hold interface if operators need it;
- privacy-safe audit export format;
- consent-sensitive feature registry for indexing/search/semantic plugins;
- policy documentation templates for operators;
- compliance-oriented test fixtures for delete/export/audit behavior.

Acceptance criteria:

- admin access is authenticated, authorized, and audited;
- delete/export workflows are deterministic and documented;
- optional indexing/search features have explicit privacy controls;
- audit exports avoid leaking tokens, proofs, private bodies, or unnecessary identifiers;
- compliance features do not weaken Solid access control.

Implementation notes:

- Keep compliance hooks modular; not every deployment has the same legal obligations.
- Do not hard-code jurisdiction-specific policy into core protocol behavior.

## Phase 30: Plugin and extension architecture

Goal: allow safe extension of storage, authn, authz, indexing, compression, notifications, and DID resolution without destabilizing the core runtime.

Implement:

- extension point inventory and stability levels;
- plugin interface for storage adapters;
- plugin interface for DID resolvers;
- plugin interface for metadata/index sinks;
- plugin interface for notification delivery backends;
- compression codec registry with compatibility gates;
- policy-extension decision process;
- sandboxing/isolation model for high-risk plugins;
- plugin config validation and capability declarations;
- compatibility tests for plugin boundaries;
- operator docs for enabling/disabling plugins.

Acceptance criteria:

- plugins cannot bypass authn/authz unless explicitly trusted and documented;
- plugin failures degrade safely;
- plugin capabilities are visible to operators;
- unsafe plugin APIs are marked unstable/internal;
- core Solid behavior works with no plugins enabled.

Implementation notes:

- Start with compile-time/internal plugin interfaces before dynamic loading.
- Every plugin boundary needs a threat model before becoming stable.

## Phase 31: Stable native Solid release

Goal: ship a versioned, supportable native Go/Rust Solid runtime with compatibility evidence and operator-ready docs.

Implement:

- release criteria checklist;
- public conformance report;
- performance benchmark report;
- migration guide from CSS-backed sidecar mode;
- upgrade/downgrade policy;
- API and config versioning policy;
- LTS/security-fix policy;
- deprecation policy;
- production deployment reference architecture;
- backup/restore runbook;
- incident response runbook;
- known limitations document;
- signed release artifacts where applicable.

Acceptance criteria:

- stable release cannot be cut without passing conformance, security, migration, and rollback checks;
- public docs identify standard Solid behavior vs project extensions;
- operators can install, upgrade, back up, restore, and roll back;
- users and operators can disable nonessential extensions such as `did:solid`, semantic indexing, or Zstd;
- release artifacts are reproducible enough for audit and support.

Implementation notes:

- Treat this as the first product-grade release gate, not the end of development.
- After this phase, future work should be managed through versioned product roadmaps rather than open-ended implementation phases.

## Updated long-term implementation order

After Phase 17, proceed in this order unless a security issue requires reprioritization:

1. production storage engine;
2. native authorization authority;
3. Solid conformance/interoperability suite;
4. multi-tenant/operator platform;
5. federated identity and trust expansion;
6. high-performance indexing/query layer;
7. notifications and realtime productionization;
8. migration tooling;
9. security audit and formal hardening;
10. SDK/client compatibility layer;
11. clustered deployment;
12. policy and compliance framework;
13. plugin/extension architecture;
14. stable native Solid release.

## Additional stop conditions

Pause post-Phase-17 work and reassess if any of these occur:

- native runtime behavior diverges from CSS without a documented compatibility decision;
- storage metadata can diverge from resource bodies;
- authorization decisions depend on non-deterministic parser output;
- indexes reveal private resource existence or content;
- notification delivery leaks private changes;
- migration cannot produce verification reports;
- cluster mode allows DPoP replay across instances;
- plugins can bypass authn/authz or access private bodies without explicit capability grants;
- compliance features weaken Solid access control or user data ownership;
- stable release criteria become optional or undocumented.

# Canonical implementation and production-readiness status

**Status date:** 2026-07-16  
**Published release/tag:** not independently confirmed by this document  
**Release documentation present:** `v0.1.0-alpha`  
**Current development track:** `v0.2.0-beta` preparation  
**Production authority:** Community Solid Server (CSS)  
**Default safe profile:** CSS proxy with native and enforcement modes disabled

This is the first current-state reference for `solid-sidecar`. Older phase reports and release notes are historical evidence, not authoritative readiness declarations.

## Status vocabulary

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | Code exists and has meaningful tests, but production verification may remain. |
| `IMPLEMENTED_NEEDS_VERIFICATION` | Substantial code exists, but one or more required integration, compatibility, race, security, packaging, or operational checks are incomplete. |
| `PRODUCTION_CANDIDATE` | Required implementation and verification are complete for a bounded deployment profile; release approval may remain. |
| `PRODUCTION_READY` | Released, supported, operationally validated, and approved for the documented production profile. |
| `EXPERIMENTAL` | Available only behind explicit opt-in or feature gates; behavior or API may change. |
| `DEFERRED` | Intentionally postponed and not part of the current production claim. |
| `NOT_IMPLEMENTED` | No usable implementation exists, or only placeholder scaffolding exists. |

`IMPLEMENTED` never means `PRODUCTION_READY`. A parser, evaluator, transport, SDK, or runtime can be implemented while the complete deployment profile remains unsuitable for production.

## Release truth

The repository contains `docs/release-notes-v0.1.0-alpha.md`, but those notes say the matching tag was still "to be created." Until the tag/release is independently confirmed, documentation must say **release documentation exists for v0.1.0-alpha**, not that a published GitHub release has been verified.

The active engineering target is **v0.2.0-beta preparation**. No beta release is claimed.

## Component status

| Component | Implementation status | Production status | Evidence and remaining gap |
|---|---|---|---|
| Core HTTP gateway | `IMPLEMENTED` | Not production-ready as a complete product | Reverse proxy, limits, safety headers, readiness, rate limiting, and observability exist. Full release gates and external deployment evidence remain. |
| Solid-OIDC authentication | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready | Issuer discovery, JWKS, JWT verification, identity extraction, and bounded fetches exist. Full issuer/client compatibility and production matrix remain. |
| DPoP validation | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready | Proof validation, replay checks, key binding, and SDK proof generation exist. Native secure-key abstraction, nonce flow, distributed replay, and broader interop remain. |
| WebID verification | `IMPLEMENTED` | Not independently production-ready | Subject binding, profile parsing, URL validation, cache isolation, and regression tests exist. Browser/provider compatibility remains. |
| WAC parser | `IMPLEMENTED` | Shadow-use only | Parser and tests exist. Complete formal conformance, fuzzing, and authoritative enforcement evidence remain. |
| WAC evaluator | `IMPLEMENTED_NEEDS_VERIFICATION` | Shadow-use only | Evaluator exists, but production enforcement remains gated by CSS comparison evidence. |
| ACP parser | `IMPLEMENTED` | Shadow-use only | Parser and tests exist. Complete formal conformance and fuzzing remain. |
| ACP evaluator | `IMPLEMENTED_NEEDS_VERIFICATION` | Shadow-use only | Evaluator exists, but production enforcement remains gated by comparison evidence. |
| Enforcement gate | `IMPLEMENTED_NEEDS_VERIFICATION` | Disabled by default | Shadow/canary controls exist. Production-default thresholds, evidence freshness, deterministic canary assignment, and automatic rollback require completion. |
| Comparison thresholds | `IMPLEMENTED_NEEDS_VERIFICATION` | Not release-authoritative | Threshold concepts and comparison harness exist. Mandatory production defaults and signed/current evidence remain. |
| Authorization cache invalidation | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready | Cache and invalidation mechanisms exist. Cross-node, policy-epoch, and exhaustive stale-decision tests remain. |
| Storage engine | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready | Multiple backends, metadata, OCC-related behavior, quotas, tombstones, and integrity foundations exist. Transaction atomicity and backend failure guarantees remain unproven. |
| Conditional writes | `IMPLEMENTED` | Needs backend matrix verification | ETag, `If-Match`, and `If-None-Match` paths exist in storage/runtime and SDK layers. Every backend and mutation path still needs formal verification. |
| Backup/restore | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready | Hooks and foundations exist. Interrupted, corrupt, conflict, resume, and staging restore tests remain. |
| Integrity scanner | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready | Scanner foundations exist. Repair guarantees and backend fault-injection evidence remain. |
| Conformance suite | `IMPLEMENTED_NEEDS_VERIFICATION` | Not release-authoritative | HTTP/CSS comparison and compatibility foundations exist. Four-mode matrix, complete categories, and public JSON/Markdown artifacts remain. |
| TypeScript SDK | `IMPLEMENTED_NEEDS_VERIFICATION` | Beta preparation | Entry point, auth, DPoP, notifications, resource, policy, WebID, RDF, sync, HTTP, URL policy, retries, and focused tests were hardened in PRs 11-27. Full SDK-wide lint/typecheck/test/build/package and fixture imports remain. |
| Go SDK | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready | A separate SDK exists. Independent API, race, retry, bounds, cancellation, packaging, and compatibility audit remain. |
| Notifications | `EXPERIMENTAL` | Disabled/not authoritative | Client reconnect/SSE handling improved. Durable server log, subscription authorization, cursor retention, backpressure, and privacy tests remain. Events are hints only. |
| Indexing | `EXPERIMENTAL` | Disabled for production claims | Foundations exist. Authorization-at-query-time and isolation/privacy verification remain. |
| Multi-tenancy | `EXPERIMENTAL` | Not production-ready | Scaffolding exists. Isolation, cache partitioning, operator controls, and side-channel suites remain. |
| Cluster support | `NOT_IMPLEMENTED` | Not supported | Distributed replay, invalidation, rate limiting, event log, leader election, rolling upgrade, and split-brain tests remain. |
| Security audit | `IMPLEMENTED_NEEDS_VERIFICATION` | No final sign-off | Multiple audits and hardening changes exist. Threat model v1, full fuzzing, secret scan, dependency/license reports, disclosure policy, and external review closure remain. |
| Browser/PWA compatibility | `NOT_IMPLEMENTED` | Not supported as a production claim | No authoritative Playwright browser matrix or service-worker private-cache suite exists. |
| Native client compatibility | `NOT_IMPLEMENTED` | Not supported as a production claim | No runnable native reference client with secure platform key/token storage has been validated. |
| Native runtime | `EXPERIMENTAL` | Disabled by default | Runtime code exists. Durable readiness evidence, storage/recovery proof, rollback testing, and native conformance remain. |
| SAI service | `EXPERIMENTAL` | Enforcement deferred | Service and data models exist. SAI registrations or grants do not bypass WAC/ACP; authoritative SAI enforcement is deferred. |
| `did:solid` | `EXPERIMENTAL` | Disabled by default | Resolver/binding code exists with network hardening. DID identity never grants resource access by itself. |
| Transport backends | `IMPLEMENTED_NEEDS_VERIFICATION` | Not production-ready as a set | Local, HTTP, S3, and SSH/SFTP foundations exist with hardening work. Credential, endpoint, host-key, quota, and failure-path verification remain backend-specific. |

## Platform phases 18, 19, 20, and 27

These statements supersede older contradictory phase summaries.

| Phase | Canonical status | Current truth |
|---|---|---|
| Phase 18 — Production storage engine | `IMPLEMENTED_NEEDS_VERIFICATION` | This phase is no longer accurately described as "missing OCC." Conditional writes and substantial storage functionality exist. Atomic resource/metadata transactions, quota-bypass closure, and production backup/restore verification remain. |
| Phase 19 — Native authorization authority | `IMPLEMENTED_NEEDS_VERIFICATION` | More than scaffolding exists: WAC/ACP parsing/evaluation, policy discovery/cache, enforcement gates, and comparison infrastructure are present. It is not production-authoritative because current evidence and rollout gates are incomplete. |
| Phase 20 — Formal conformance suite | `IMPLEMENTED_NEEDS_VERIFICATION` | Substantial HTTP, CORS, CSS comparison, container, conditional, authn, authz, and compression test foundations exist. The complete direct/proxy/hybrid/native matrix and release artifacts remain incomplete. |
| Phase 27 — SDK/client compatibility | `IMPLEMENTED_NEEDS_VERIFICATION` | TypeScript and Go SDK foundations exist. The TypeScript SDK received extensive correctness/security hardening through PR 27. Full package/release gates, browser/PWA interop, native key adapters, Go SDK verification, and compatibility matrices remain. |

## Production profiles

### Current supported development profile

```text
Native or PWA client
  -> Solid HTTP / Solid-OIDC / DPoP
  -> solid-sidecar in CSS proxy or shadow mode
  -> CSS remains authoritative
```

This is a development and integration profile, not a production-readiness claim.

### First production-candidate target

CSS proxy remains authoritative. Native mode is disabled. Authorization enforcement is shadow-only or an explicitly evidence-gated canary. Notifications, indexing, SAI enforcement, DID resolution, and cluster mode remain disabled or experimental unless their roadmap phases are completed.

### Later native-runtime target

The sidecar becomes authoritative only after native conformance, storage atomicity, durable readiness evidence, notification privacy/replay, recovery, security review, soak testing, and rollback evidence are complete.

## Non-negotiable safety boundaries

- CSS remains the compatibility and rollback authority until the CSS-proxy production candidate is approved.
- `did:solid` identity never grants resource access by itself.
- SAI application registrations and grants do not bypass WAC/ACP.
- Parse or policy failures never become allow decisions.
- Native and enforcement modes remain disabled by default.
- Notifications are change hints and never authoritative resource state.
- Unsafe client URLs must not become arbitrary outbound requests.
- Retries must not duplicate non-idempotent writes.
- Private resource existence and identifiers must not leak through errors, logs, metrics, caches, notifications, or indexes.

## Roadmap completion summary

No roadmap phase should be called complete merely because its primary code exists. Under the production-readiness Definition of Done:

- Roadmap PR-2 (TypeScript SDK) is the most advanced, but still `IMPLEMENTED_NEEDS_VERIFICATION`.
- Roadmap PR-1 is complete only when this document, the readiness plan, README, and stale status documents agree and CI/review pass.
- Browser/PWA, Solid JavaScript compatibility, native reference client, soak, release-candidate, native-authority, and cluster phases remain incomplete.

## Updating this document

Every readiness-changing pull request must update this file or explicitly state why no status changes. A status may advance only when the implementation, meaningful tests, applicable integration/race/security tests, documentation, CI, and rollback/disable evidence all exist.
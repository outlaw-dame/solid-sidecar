# Native and PWA production-readiness plan

This document is the implementation entry point for making `solid-sidecar` suitable for browser/PWA and native clients. The authoritative current-state table is [`canonical-status.md`](canonical-status.md).

## Immediate production target

```text
Native or PWA client
  -> Solid HTTP / Solid-OIDC / DPoP
  -> solid-sidecar
  -> CSS remains the compatibility, authorization, and rollback authority
```

The immediate target is a **CSS-proxy production candidate**. Native runtime authority must not be claimed before that target is complete.

## Later production target

```text
Native or PWA client
  -> Solid HTTP / Solid-OIDC / DPoP
  -> solid-sidecar native runtime
  -> native storage, authorization, notifications, indexing, and policy enforcement
```

The later target requires current readiness evidence, native conformance, storage/recovery verification, privacy-safe notifications and indexing, tested rollback, security sign-off, and staging soak evidence.

## Required status model

All readiness documents and pull requests use:

- `IMPLEMENTED`
- `IMPLEMENTED_NEEDS_VERIFICATION`
- `PRODUCTION_CANDIDATE`
- `PRODUCTION_READY`
- `EXPERIMENTAL`
- `DEFERRED`
- `NOT_IMPLEMENTED`

`Complete` without a readiness qualifier is not an accepted status.

## Current milestone state

| Milestone | State | Summary |
|---|---|---|
| SDK beta quality | `IMPLEMENTED_NEEDS_VERIFICATION` | TypeScript SDK components received extensive hardening; full SDK release gates, secure signer abstraction, Go SDK audit, and compatibility/version policy remain. |
| PWA production candidate | `NOT_IMPLEMENTED` | Browser matrix, service-worker privacy tests, Solid JavaScript client compatibility, formal conformance artifacts, and consolidated security/release gates remain. |
| Native client production candidate | `NOT_IMPLEMENTED` | Native reference client, secure platform key adapter, storage fault-injection proof, staging soak, and CSS-proxy release profile remain. |
| Native runtime production candidate | `EXPERIMENTAL` | Native code exists, but durable readiness evidence, native conformance, recovery, notifications, and rollback proof remain. |
| Clustered stable release | `NOT_IMPLEMENTED` | Distributed replay, invalidation, rate limiting, event log, leadership, upgrade, and split-brain behavior remain. |

## Execution order

### P0 — close claim-versus-evidence gaps

1. Status reconciliation and canonical readiness state.
2. Finish TypeScript SDK-wide correctness, packaging, and release gates.
3. Complete formal CSS/direct/proxy/hybrid/native conformance reporting.
4. Make production enforcement thresholds and rollback mandatory.
5. Complete formal security hardening and disclosure workflow.
6. Consolidate CI and release evidence.

### P1 — prove client compatibility and isolation

1. DPoP secure signer and native adapter abstraction.
2. Go SDK audit and hardening.
3. SDK versioning and compatibility policy.
4. Browser/PWA Playwright matrix.
5. Existing Solid JavaScript client compatibility.
6. Storage atomicity, quota, backup, and restore verification.
7. IDOR, tenant/storage-root isolation, cache, notification, index, and side-channel suite.

### P2 — production candidate evidence

1. Notifications productionization.
2. Runnable native reference client.
3. Staging load, failure injection, and soak.
4. CSS-proxy production-candidate release.

### Later native authority

1. Durable native readiness evidence.
2. Native-runtime production candidate.
3. Multi-instance and clustered readiness.

## Definition of done

A phase can advance to `PRODUCTION_CANDIDATE` only when all applicable items exist:

- implementation;
- meaningful unit tests;
- integration and interoperability tests;
- race tests for race-sensitive Go code;
- adversarial and failure tests;
- accurate documentation and compatibility matrix;
- clean CI and required artifacts;
- no unresolved review threads;
- explicit disable or rollback behavior;
- no stale readiness claims.

Code presence or a focused unit test alone is insufficient.

## Global safety invariants

1. `did:solid` identity never grants resource access by itself.
2. SAI registrations or grants never bypass WAC/ACP unless a future authorized enforcement profile explicitly permits it.
3. Tokens, DPoP proofs, private keys, credentials, PKCE verifiers, private bodies, and raw policies are never logged.
4. Policy parsing and evaluation failures fail closed for authoritative decisions.
5. Stale authorization decisions do not survive resource, policy, identity, configuration, evaluator, parser, backend, or release changes.
6. Client-controlled URLs cannot become arbitrary outbound requests.
7. Unsupported preconditions fail closed.
8. Native and enforcement modes remain disabled by default.
9. Notifications are hints and require resource revalidation.
10. Private existence and identifiers do not leak through errors, notifications, indexes, metrics, logs, or cache keys.
11. Automatic retries never duplicate non-idempotent writes.
12. Every production feature has a tested disable or rollback path.

## Pull-request evidence checklist

Every readiness pull request must include:

- exact readiness gap closed;
- existing implementation reused;
- recent overlapping commits and open-PR conflict check;
- affected security invariants;
- rollback/disable behavior;
- unit and integration tests added;
- CI job and artifacts proving completion;
- documentation updates;
- known limitations and unverified behavior.

## Current next phase

After this reconciliation phase, finish the cross-cutting remainder of TypeScript SDK hardening rather than creating additional per-file readiness claims. The next SDK work must prove the complete package through one authoritative workflow: install, typecheck, lint, tests, build, package dry-run, and import fixtures.
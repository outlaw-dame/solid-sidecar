# Phase map

This file is retained for compatibility with older links.

The previous phase map used a four-state model that conflated implementation, shadow-mode availability, and production readiness. It also contained stale claims that Phase 18 lacked conditional writes, Phase 20 had only minimal scaffolding, and Phase 27 had not started.

Use these authoritative references instead:

- [`canonical-status.md`](canonical-status.md) — current component and phase state
- [`native-pwa-production-readiness.md`](native-pwa-production-readiness.md) — production-readiness execution plan and milestones
- [`solid-runtime-roadmap-index.md`](solid-runtime-roadmap-index.md) — historical phase-roadmap index

## Canonical corrections

| Historical phase | Current canonical status |
|---|---|
| Phase 18 — Production storage engine | `IMPLEMENTED_NEEDS_VERIFICATION`: conditional writes, OCC-related behavior, multiple backends, quotas, tombstones, backup/restore hooks, and integrity foundations exist; transaction atomicity, quota-path closure, and production recovery evidence remain. |
| Phase 19 — Native authorization authority | `IMPLEMENTED_NEEDS_VERIFICATION`: policy discovery/cache, WAC/ACP parsing and evaluation, comparison infrastructure, and gates exist; native authority remains disabled pending current evidence and rollback verification. |
| Phase 20 — Formal conformance suite | `IMPLEMENTED_NEEDS_VERIFICATION`: substantial HTTP/CORS/container/conditional/authn/authz/compression and CSS comparison foundations exist; the complete direct/proxy/hybrid/native matrix and public release artifacts remain. |
| Phase 27 — SDK/client compatibility | `IMPLEMENTED_NEEDS_VERIFICATION`: TypeScript and Go SDK foundations exist; the TypeScript SDK was extensively hardened through repository PR 27; full package gates, browser/PWA, native signer, Go SDK, and compatibility evidence remain. |

## Status vocabulary

Only these states should be used for current readiness claims:

- `IMPLEMENTED`
- `IMPLEMENTED_NEEDS_VERIFICATION`
- `PRODUCTION_CANDIDATE`
- `PRODUCTION_READY`
- `EXPERIMENTAL`
- `DEFERRED`
- `NOT_IMPLEMENTED`

Historical phase completion does not imply that a component or deployment profile is production-ready.
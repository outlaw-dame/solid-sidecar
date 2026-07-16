# Implementation status

This file is retained as a compatibility pointer for older links.

The authoritative current-state reference is:

- [`canonical-status.md`](canonical-status.md)

The implementation and production-readiness plan for native and PWA clients is:

- [`native-pwa-production-readiness.md`](native-pwa-production-readiness.md)

## Why this file was replaced

The previous version mixed code-presence claims, phase completion, shadow-mode availability, and production readiness. It described several components as “production-ready” while also stating that CSS remained authoritative, enforcement was shadow-only, native mode required evidence, notifications were incomplete, and the release was alpha.

Those concepts are now separated through the canonical statuses:

- `IMPLEMENTED`
- `IMPLEMENTED_NEEDS_VERIFICATION`
- `PRODUCTION_CANDIDATE`
- `PRODUCTION_READY`
- `EXPERIMENTAL`
- `DEFERRED`
- `NOT_IMPLEMENTED`

## Critical corrections

- Phase 18 is not merely “missing OCC.” Conditional writes and substantial storage functionality exist; transaction atomicity, quota-path verification, and production backup/restore evidence remain.
- Phase 19 is more than scaffolding, but native authorization is not production-authoritative.
- Phase 20 has substantial conformance and CSS-comparison foundations, but the complete four-mode matrix and public release artifacts remain incomplete.
- Phase 27 contains TypeScript and Go SDK foundations. The TypeScript SDK received extensive hardening through repository PR 27, but complete SDK-wide release gates and browser/native compatibility evidence remain.
- Notifications are experimental change hints, not production-ready state.
- Native and enforcement modes remain disabled by default.
- `did:solid` and SAI identity/application state never grant access by themselves.

Historical phase documents and release notes remain useful evidence, but they must not override `canonical-status.md`.
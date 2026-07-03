# Solid Runtime Roadmap Index

This index ties the production implementation plan to the expanded roadmap documents.

Start here:

1. `docs/repository-audit-2026-07-02.md` — latest reconciliation of direct-to-main work, roadmap drift, and next safe implementation order.
2. `docs/implementation-status.md` — current done/missing audit.
3. `docs/production-implementation-plan.md` — production-readiness reset point.
4. `docs/solid-runtime-phase-roadmap.md` — expanded Go/Rust Solid runtime roadmap through Phase 17.
5. `docs/solid-platform-maturity-phases.md` — post-Phase-17 platform/runtime maturity roadmap through Phase 31.
6. `docs/compression-compatibility.md` — Gzip/Zstd compatibility and implementation plan.
7. `docs/did-solid-method.md` — project-defined `did:solid` method plan.

## Current implementation priority

The expanded roadmap preserves the current safety boundary:

- CSS remains authoritative.
- Authorization remains non-enforcing until the documented comparison, canary, bypass, and rollback controls exist.
- Shadow mode comes before enforcement.
- DID support cannot grant access by itself.
- Compression must preserve HTTP/Solid/CSS compatibility.
- Native runtime work after Phase 17 must keep CSS compatibility evidence and rollback controls until a stable release explicitly retires a CSS-backed mode.

Before continuing phase work, check `docs/repository-audit-2026-07-02.md`. Recent direct-to-main work has moved the repository beyond several roadmap assumptions, and some older phase-completion docs now conflict with current code.

Immediate next implementation order:

1. Reconcile status docs so future work distinguishes scaffolded, shadow-complete, production-ready, and blocked phases.
2. Verify CI/build/test status after recent direct-to-main work.
3. Add storage conditional write / optimistic concurrency semantics for Phase 18.
4. Harden identity/DID/S3/SSH security surfaces.
5. Clarify SAI implemented subset vs enforcement readiness.
6. Gate native/hybrid runtime modes behind explicit readiness controls.

## Post-Phase-17 maturity order

After Phase 17, proceed according to `docs/solid-platform-maturity-phases.md`:

18. production storage engine;
19. native authorization authority;
20. Solid conformance/interoperability suite;
21. multi-tenant/operator platform;
22. federated identity and trust expansion;
23. high-performance indexing/query layer;
24. notifications and realtime productionization;
25. migration tooling;
26. security audit and formal hardening;
27. SDK/client compatibility layer;
28. clustered deployment;
29. policy and compliance framework;
30. plugin/extension architecture;
31. stable native Solid release.

## Documentation boundaries

These docs are repository-local implementation plans. They do not claim that `did:solid` is an external standard, and they do not authorize production enforcement before the required comparison, canary, bypass, and rollback controls exist.

Do not blend in local-first P2P, ActivityPub, ATProto, or other project roadmaps unless a future document explicitly adds them to this repository's Solid scope.

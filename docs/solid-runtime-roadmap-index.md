# Solid Runtime Roadmap Index

This index ties the production implementation plan to the expanded roadmap documents.

Start here:

1. `docs/implementation-status.md` — current done/missing audit.
2. `docs/production-implementation-plan.md` — production-readiness reset point.
3. `docs/solid-runtime-phase-roadmap.md` — expanded Go/Rust Solid runtime roadmap.
4. `docs/compression-compatibility.md` — Gzip/Zstd compatibility and implementation plan.
5. `docs/did-solid-method.md` — project-defined `did:solid` method plan.

## Current implementation priority

The expanded roadmap preserves the current safety boundary:

- CSS remains authoritative.
- Authorization remains non-enforcing.
- Shadow mode comes before enforcement.
- DID support cannot grant access by itself.
- Compression must preserve HTTP/Solid/CSS compatibility.

Immediate next implementation order:

1. DPoP confirmation and key-binding.
2. Authn middleware and trusted identity injection.
3. Live WAC/ACP policy discovery.
4. Rust RDF parser boundary.
5. WAC parser and evaluator.
6. CSS behavior comparison harness.
7. Gzip compression compatibility scaffolding.
8. Zstd compression behind explicit config gates.
9. `did:solid` method design finalization.
10. `did:solid` resolver test vectors.
11. Enforcement gate design.

## Documentation boundaries

These docs are repository-local implementation plans. They do not claim that `did:solid` is an external standard, and they do not authorize production enforcement before the required comparison, canary, bypass, and rollback controls exist.

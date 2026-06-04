# Solid Policy Kernel

The Rust policy kernel is an internal deterministic boundary for future Solid authorization work. It is intentionally introduced in shadow mode so the sidecar can evolve toward policy evaluation without replacing Community Solid Server as the current Solid protocol and authorization authority.

## Current status

Implemented in this phase:

- JSON contract schemas for authorization requests and decisions;
- a Rust workspace under `rust/`;
- a `solid-policy-kernel` crate;
- typed request, decision, reason-code, audit, and policy-document structures;
- deterministic request and policy hashing for audit correlation;
- conservative input validation for schema version, request ID, method, requested access modes, and resource URI shape;
- shadow-mode behavior that returns `abstain` for valid requests;
- tests covering abstain behavior, invalid input rejection, deterministic hashing, and JSON contract naming.

Not implemented yet:

- WAC parsing;
- ACP parsing;
- SAI policy evaluation;
- RDF parsing or canonicalization;
- issuer/WebID authorization decisions;
- Go sidecar runtime integration;
- production enforcement.

## Decision model

The kernel emits one of three decisions:

- `allow`: reserved for future policy-backed authorization decisions;
- `deny`: used only for invalid or unsafe kernel inputs in the current phase;
- `abstain`: used for valid requests while the kernel is in shadow mode.

The Go sidecar must treat `abstain` as “do not decide here; continue to CSS.” This is the critical safety rule for this phase.

## Audit model

Every decision includes:

- `request_hash`: deterministic hash of the stable request fields;
- `policy_hash`: deterministic hash of policy-document references.

These hashes are for audit correlation and drift detection. They are not authorization proofs, signatures, or content integrity claims by themselves.

## Contract versioning

The first contract version is `authz.v1`. Future changes must either be backwards-compatible or introduce a new schema version. The kernel rejects unsupported schema versions with `unsupported_schema_version`.

## Safety boundaries

1. CSS remains the source of truth for Solid authorization.
2. The Rust kernel is not wired into request handling yet.
3. No `allow` decision should be trusted until WAC/ACP/SAI support has been implemented and tested with golden fixtures.
4. Deny decisions in this phase only mean the kernel rejected its own input contract as invalid or unsafe.
5. Production enforcement requires explicit Go integration, metrics, replay-safe request identity, decision caching rules, and migration gates.

## Local commands

From the repository root:

```sh
cd rust
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

The main Go CI currently does not depend on the Rust workspace. Rust CI should be added only after the current Go CI is stable.

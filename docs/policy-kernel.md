# Solid Policy Kernel

The Rust policy kernel is an internal deterministic boundary for future Solid authorization work. Phase 4 is complete: the kernel and Go sidecar now share a tested `authz.v1` contract boundary in shadow mode. The boundary is intentionally non-enforcing and does not replace Community Solid Server as the current Solid protocol and authorization authority.

## Current status

Implemented:

- JSON contract schemas for authorization requests, decisions, and the shared fixture manifest;
- a Rust workspace under `rust/`;
- a `solid-policy-kernel` crate;
- typed request, decision, reason-code, audit, and policy-document structures;
- deterministic request and policy hashing for audit correlation;
- conservative input validation for schema version, request ID, method, requested access modes, and resource URI shape;
- malformed request-ID sanitization for decision correlation;
- shadow-mode behavior that returns `abstain` for valid requests;
- structured `deny` decisions for invalid kernel inputs;
- a `solid-policy-kernel-eval` CLI that reads an authz request JSON document from stdin or a file and writes the deterministic decision JSON to stdout;
- shared Go/Rust fixture tests covering valid shadow decisions, invalid-contract decisions, deterministic hashes, manifest coverage, manifest drift protection, strict fixture filenames, and log/privacy expectations on the Go side.

Not implemented yet:

- WAC parsing;
- ACP parsing;
- SAI policy evaluation;
- RDF parsing or canonicalization;
- issuer/WebID authorization decisions;
- Go sidecar runtime integration with the CLI or library;
- production enforcement.

## Decision model

The kernel emits one of three decisions:

- `allow`: reserved for future policy-backed authorization decisions;
- `deny`: used only for invalid or unsafe kernel inputs in the current phase;
- `abstain`: used for valid requests while the kernel is in shadow mode.

The Go sidecar must treat `abstain` as “do not decide here; continue to CSS.” Current Go middleware also remains non-enforcing for shadow `deny` decisions; they are logged for observability and drift detection but do not block CSS.

## CLI evaluator

The CLI is a future integration seam for the Go sidecar. It is currently intended for deterministic contract testing and local inspection only.

From the repository root:

```sh
cd rust
cargo run -p solid-policy-kernel --bin solid-policy-kernel-eval -- ../contracts/fixtures/authz_request.valid.json
```

The same request can be sent on stdin:

```sh
cd rust
cargo run -p solid-policy-kernel --bin solid-policy-kernel-eval < ../contracts/fixtures/authz_request.valid.json
```

The CLI writes only the decision JSON to stdout. Decode/read errors are written to stderr and exit non-zero.

## Audit model

Every decision includes:

- `request_hash`: deterministic hash of the stable request fields;
- `policy_hash`: deterministic hash of policy-document references.

These hashes are for audit correlation and drift detection. They are not authorization proofs, signatures, or content integrity claims by themselves.

## Contract versioning

The first contract version is `authz.v1`. Future changes must either be backwards-compatible or introduce a new schema version. The kernel rejects unsupported schema versions with `unsupported_schema_version`.

The fixture manifest version is `authz.fixture-manifest.v1`. Go and Rust tests both read the same manifest and reject duplicate entries, orphan fixture files, invalid fixture names, and unexpected manifest fields.

## Shadow logging boundary

Go authz shadow middleware validates evaluator decisions before emitting normal shadow-decision logs. Invalid evaluator output is logged as a privacy-safe warning and still passes through to CSS.

Shadow log guarantees:

- warning reasons use stable labels instead of raw error text;
- warning and decision log messages and field names are centralized constants;
- warning logs include request ID correlation;
- warning logs use path-only request information and do not emit query strings;
- normal shadow-decision logs are emitted only after decision validation succeeds.

## Safety boundaries

1. CSS remains the source of truth for Solid authorization.
2. The Rust kernel is not wired into live request handling yet.
3. No `allow` decision should be trusted until WAC/ACP/SAI support has been implemented and tested with golden fixtures.
4. Deny decisions in this phase only mean the kernel rejected its own input contract as invalid or unsafe.
5. Production enforcement requires explicit Go integration, metrics, replay-safe request identity, decision caching rules, and migration gates.

## Local commands

From the repository root:

```sh
bash scripts/verify.sh rust
```

From the Rust workspace:

```sh
cd rust
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --lib -- -D warnings
```

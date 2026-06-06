# Phase 4 Completion: Authorization Contract and Policy-Kernel Shadow Mode

Phase 4 is complete when the repository has a stable, tested, non-enforcing authorization-contract boundary between the Go sidecar and the Rust policy-kernel scaffold. This phase does not make Solid authorization decisions and does not replace Community Solid Server (CSS).

## Completed scope

Phase 4 completed the following work:

1. Authz request and decision contracts exist under `contracts/`.
2. Go contract builders, codecs, validators, audit hashing, and non-enforcing shadow middleware exist under `internal/authz/`.
3. Rust contract types, deterministic shadow evaluator, CLI seam, and shared fixture tests exist under `rust/crates/solid-policy-kernel/`.
4. Shared fixtures and a manifest lock Go/Rust parity for valid shadow requests and invalid-contract deny outcomes.
5. The fixture manifest has a schema, strict filename validation, duplicate-entry checks, and orphan-file coverage in Go and Rust.
6. Malformed request IDs are sanitized into valid deterministic surrogate decision IDs.
7. Invalid contract inputs produce structured deny decisions while valid shadow-mode inputs produce abstain decisions.
8. Go middleware validates evaluator decisions before normal shadow logging.
9. Shadow deny and invalid evaluator outputs remain non-enforcing and always continue to CSS.
10. Authz shadow logs are privacy-safe: stable field names, stable warning reason labels, no raw error text, no query strings, no WebID/client-ID leakage in the tested log paths.
11. CI/local verification has a single entrypoint through `scripts/verify.sh` for Go and Rust checks.

## Phase 4 guarantees

The following guarantees define the completed Phase 4 boundary:

- CSS remains the only production Solid authorization authority.
- The Go authz shadow middleware is observational and non-enforcing.
- A valid `authz.v1` request evaluated in shadow mode returns `abstain`.
- Invalid kernel inputs return deterministic structured `deny` decisions for the kernel contract only; they do not block CSS in the Go middleware.
- Go and Rust must read the same fixture manifest and agree on expected decisions.
- Request and decision audit hashes are deterministic correlation fields, not authorization proofs.
- Log output must remain privacy-safe and must not include raw evaluator/build errors or request query strings.

## Phase 4 non-goals

The following are intentionally not part of Phase 4:

- WAC parsing or enforcement.
- ACP parsing or enforcement.
- SAI policy evaluation.
- RDF parsing or canonicalization.
- Issuer/WebID authorization decisions.
- Rust runtime integration into live Go request handling.
- Decision caching.
- Production policy enforcement.
- Replacing CSS as the Solid protocol authority.

These items belong to later phases and must be introduced behind explicit contracts, golden fixtures, observability, and migration gates.

## Completion checklist

Before treating Phase 4 as complete, the following checks should pass in an environment with Go and Rust toolchains installed:

```sh
bash scripts/verify.sh all
```

Equivalent split checks:

```sh
bash scripts/verify.sh go
bash scripts/verify.sh rust
```

The Go path checks formatting, vet, tests, race tests, and the sidecar build. The Rust path checks formatting, workspace tests, and library clippy with warnings denied.

## Handoff to Phase 5

Phase 5 should start from this assumption: the contract boundary is stable enough to begin explicit runtime integration design, but enforcement remains forbidden until WAC/ACP/SAI semantics, issuer/WebID identity behavior, cache semantics, failure modes, and rollout gates are fully specified and tested.

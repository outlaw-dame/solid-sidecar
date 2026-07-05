# Repository Audit and Roadmap Reconciliation — 2026-07-02

This audit reconciles the current `main` branch with the implementation roadmaps and recent direct-to-main work. It is scoped only to this repository's Solid Go/Rust sidecar/runtime work.

## Executive summary

The repository has advanced significantly beyond the earlier “CSS-front-door plus shadow shell” baseline. Several roadmap phases now have at least partial or substantial implementation artifacts on `main`, including:

- Phase 1 authn DPoP/JWT key-binding work;
- Phase 2 Solid HTTP request compliance work;
- live policy discovery/loading/cache work;
- RDF parser boundary scaffolding;
- WAC parser and evaluator work;
- ACP parser and evaluator work;
- CSS behavior comparison harness;
- enforcement gate scaffolding;
- `did:solid` parser/resolver/binding and canonical agent identity work;
- SAI package implementation despite older docs saying SAI is deferred;
- native runtime package scaffolding for gateway/storage/metadata/RDF/policy/notification/multistorage/migration layers;
- fixture distribution transport work through Phases 33/34;
- Phase 17 load-test infrastructure.

The highest-priority next work is not to blindly continue the old roadmap. The repo first needs status cleanup, verification, and hardening because several documents now conflict with one another and some implementation claims are stronger than the code evidence supports.

## Recent PR state

Open PRs: none.

Recently merged PRs visible in the connector:

1. PR #1 — documented Solid runtime roadmap, compression compatibility, and `did:solid`.
2. PR #2 — added DPoP token/proof key-binding checks.
3. PR #3 — documented post-Phase-17 platform maturity phases.

## Recent direct-to-main work observed

Recent commits on `main` include substantial direct work beyond the merged PRs:

- `b94d7286` — S3 SDK integration and SSH/SFTP fixture transport functionality.
- `260faf36` — Phase 17 load tests.
- `87b3e860` — Phase 15 hardening and Phase 16 implementation.
- `e769cddb` — Phase 15 native Go/Rust Solid runtime implementation.
- `126028c2` — SAI hardening with security middleware.
- `db9bb79d` — SAI support implementation.
- `0266a288` — Phase 10 canonical agent model with `did:solid`.
- `9a87f918` — Phase 9 DID resolver and identity binding.
- Multiple Phase 2 commits for HTTP method/media-type validation, CORS tests, storage-root validation, and container/description-resource behavior.

## Current verified implementation areas

### Authn and identity

Verified files:

- `internal/authn/dpop.go`
- `internal/authn/dpop_binding.go`
- `internal/authn/identity_jwt.go`
- `internal/authn/agent_identity.go`
- `internal/authn/did_binding.go`
- `internal/identity/did_parser.go`
- `internal/identity/did_resolver.go`
- `internal/identity/did_types.go`

Current verified shape:

- DPoP request verification validates proof structure and request binding.
- Token/proof key binding has been added via `cnf.jkt` extraction and proof JWK thumbprint comparison.
- The request-path binding check is performed inside `DPoPVerifier.VerifyRequest`, after proof parsing/signature verification and `ath` checks.
- `AgentIdentity` now exists in `internal/authn`, combining WebID, optional DID, issuer, client ID, DPoP key thumbprint, assurance level, and verification source.
- DID binding code exists and is disabled by default.
- DID/WebID binding remains non-authorizing: DID ownership alone must not grant resource access.

Concerns/gaps:

- `AgentIdentity.String()` currently prints raw WebID, issuer, client ID, and DID when present. `RedactedString()` exists, but the raw `String()` method is risky if used in logs.
- DID backlink parsing uses simple string search rather than a proper RDF parser boundary.
- DID resolver HTTP fetch path needs a deeper SSRF/redirect/private-network review before enabling remote resolution broadly.
- Authn e2e with real signed issuer tokens is still a priority.

### Solid HTTP compatibility and gateway safety

Verified through docs/status and search results:

- method/media-type validation exists for write requests;
- HTTP method compatibility fixtures exist;
- CORS behavior tests exist;
- storage-root validation exists;
- container slash redirect and description-resource handling exist.

Concerns/gaps:

- Need a real CI/e2e evidence check after recent direct-to-main commits.
- Need staged traffic comparison evidence before treating this as production-ready behavior.

### Authz policy discovery, parsing, and evaluation

Verified through implementation status and repository search:

- policy source loading and cache integration are documented as complete;
- RDF parser boundary scaffolding exists;
- WAC parser and WAC evaluator work exist;
- ACP parser and ACP evaluator work exist;
- CSS comparison harness exists;
- enforcement gate exists.

Concerns/gaps:

- Status docs still say enforcement is blocked, which is the correct safety stance.
- However, docs also mark many subcomponents as “complete.” That should be clarified as “complete as shadow/scaffold implementation,” not production enforcement-ready.
- WAC/ACP evaluator behavior still needs rigorous comparison against CSS and Solid test fixtures before enforcement.
- Decision cache for enforcement and canary rollout controls need verification or implementation.

### SAI

Verified files:

- `internal/sai/service.go`
- `internal/sai/service_test.go`
- SAI-related type/storage/security files from repository search and commit history.

Current shape:

- A real `internal/sai` package exists.
- `SAIService` defines storage-backed flows for applications, registrations, access grants, data registrations, data grants, data instances, shape trees, and authorization agents.
- Older docs still say SAI is explicitly deferred, while newer commits claim SAI implementation and hardening.

Concern:

- This is the clearest documentation contradiction in the repository. SAI is no longer merely deferred. The docs should distinguish:
  - SAI service/model scaffolding exists;
  - SAI parser/evaluator/enforcement semantics remain not production-authoritative unless separately proven.

### Native Go/Rust runtime path

Verified files:

- `internal/runtime/runtime.go`
- `internal/runtime/storage.go`
- runtime layer files discovered by search and commit history.

Current shape:

- `internal/runtime` package exists.
- `Runtime` initializes eight layers:
  1. gateway compatibility;
  2. storage abstraction;
  3. metadata/index;
  4. RDF graph/index;
  5. policy engine;
  6. notification/live-update;
  7. multi-storage/multi-tenant;
  8. CSS migration/compatibility.
- Runtime modes exist: `css_proxy`, `hybrid`, and `native`.
- Storage abstraction interface supports `Get`, `Put`, `Delete`, `List`, `Exists`, `Head`, `Close`, and `HealthCheck`.

Concerns/gaps:

- This is substantial scaffolding, but it should not yet be treated as a stable native Solid runtime.
- Storage interface currently lacks explicit concurrency/precondition operations despite Phase 18 documentation calling for OCC/ETag/conditional write semantics.
- Native mode transition currently appears possible in code, but production readiness gates and compatibility evidence need careful review before native mode is exposed operationally.
- The runtime layer should be audited for whether policy enforcement, index filtering, notification delivery, and storage writes actually preserve Solid semantics end to end.

### Fixture distribution Phases 33/34

Verified files:

- `internal/authz/fixture_distribution_transport.go`
- `internal/authz/fixture_distribution_transport_test.go`
- `docs/phase-33-completion.md`
- `docs/phase-34-completion.md`

Current shape:

- HTTP transport exists.
- Local file transport exists with atomic writes, validation, permission control, and hash verification.
- S3 transport now imports AWS SDK v2 and has credential/default-chain configuration and S3 client initialization.
- SSH transport now imports `golang.org/x/crypto/ssh` and `github.com/pkg/sftp` and appears to implement SFTP/SSH upload paths.

Documentation contradiction:

- `docs/phase-33-completion.md` says LocalFile/S3/SSH transports are stubs.
- `docs/phase-34-completion.md` says S3/SSH SDK integration is pending.
- The current code and latest commit message say S3 and SSH SDK integration has been added.

This needs documentation cleanup before future agents rely on the Phase 33/34 completion docs.

### Dependencies and CI

Verified files:

- `go.mod`
- `.github/workflows/ci.yml`

Current shape:

- `go.mod` now declares `go 1.25.0` and adds AWS SDK v2, SFTP, and `golang.org/x/crypto` dependencies.
- CI uses `actions/setup-go` with `go-version: '1.25.x'` for Go build/test and stable for govulncheck.

Concerns/gaps:

- The connector returned no combined status entries and no workflow runs for the latest direct-to-main commit checked.
- `go.mod` moving from Go 1.22 to Go 1.25 is a major baseline change and should be explicitly documented in CI/runbooks if intentional.
- The S3/SSH additions expand dependency and security surface significantly; this should trigger a focused supply-chain and secret-handling review.
- `docs/transport-security-reconciliation.md` supersedes the older fixture transport audit until HTTP/S3/SSH network, credential, and host-key hardening lands.

## Roadmap reconciliation

### Phases that now appear at least partially implemented

- Phase 1: Authn trust completion — partially/substantially implemented, but real signed-token e2e remains.
- Phase 2: Solid HTTP request compliance hardening — documented complete, pending CI/staging evidence.
- Phase 3: Live policy discovery — substantially implemented in shadow mode.
- Phase 4: RDF parser boundary — scaffolded/partially implemented.
- Phase 5: WAC parser/evaluator — implemented in shadow/scaffold form.
- Phase 6: ACP parser/evaluator — implemented in shadow/scaffold form.
- Phase 7: SAI decision/parser boundary — docs are stale; SAI service exists, enforcement semantics still require clarification.
- Phase 8–10: `did:solid` design/resolver/canonical identity — implemented in code, still disabled-by-default and non-authorizing.
- Phase 11: CSS behavior comparison harness — implemented according to status doc.
- Phase 14: Enforcement gates/canary — enforcement gate exists, but production canary/rollback evidence needs review.
- Phase 15–16: native runtime and notifications/indexing — implemented as runtime scaffolding; not production mature.
- Phase 17: load tests/production hardening — load-test infrastructure exists, but full production hardening is not complete.

### Phases that should remain future/maturity work

- Phase 18: Production storage engine — not complete; storage abstraction exists but needs concurrency/preconditions/OCC, durable backends, quotas, tombstones, migration-safe layout, and integrity scanning.
- Phase 19: Native authorization authority — not complete; enforcement-ready proof and CSS comparison thresholds are missing.
- Phase 20: Formal conformance/interoperability suite — not complete.
- Phase 21: Multi-tenant/operator platform — partially scaffolded, not complete.
- Phase 22: Federated identity/trust expansion — partially scaffolded, not complete.
- Phase 23: High-performance indexing/query layer — partially scaffolded, not complete.
- Phase 24: Notifications realtime productionization — partially scaffolded, not complete.
- Phase 25: Migration tooling — partially scaffolded, not complete.
- Phase 26: Security audit/formal hardening — not complete.
- Phase 27: SDK/client compatibility layer — not complete.
- Phase 28: Clustered deployment — not complete.
- Phase 29: Policy/compliance framework — not complete.
- Phase 30: Plugin/extension architecture — not complete.
- Phase 31: Stable native Solid release — not complete.

## Highest-risk issues found

1. **Status drift:** README and roadmap docs understate how much code exists, while some phase-completion docs overstate readiness.
2. **SAI contradiction:** docs say deferred, code implements SAI service. This must be clarified before more SAI work proceeds.
3. **Native mode safety:** runtime has `native` and `hybrid` modes, but stable native Solid behavior is not proven.
4. **Storage concurrency gap:** storage abstraction lacks explicit OCC/conditional write API despite Phase 18 requirements.
5. **DID privacy/logging risk:** raw identity strings can appear through `AgentIdentity.String()` if used carelessly.
6. **Remote resolver/network risk:** DID/WebID fetch paths need deeper SSRF/private-network/redirect hardening review.
7. **Transport security surface:** AWS SDK and SSH/SFTP integration greatly expand dependency, credential, and network risk.
8. **Docs Phase 33/34 stale:** transport docs no longer match current code.
9. **CI evidence gap:** latest direct-to-main commit checked had no visible status/workflow result from the connector.
10. **Go version baseline change:** `go.mod` and CI now use Go 1.25.x and this should be treated as an intentional platform requirement if retained.

## Recommended next work

Proceed in this order:

1. **Status reconciliation PR**
   - update README current status;
   - update `docs/implementation-status.md` to distinguish shadow/scaffold/production-ready;
   - update SAI section to say service exists but enforcement semantics are not production-authoritative;
   - update Phase 33/34 docs to reflect actual S3/SSH state;
   - add a phase map showing implemented vs scaffold vs blocked.

2. **CI/build verification PR or run**
   - confirm `go test ./...`, `go vet`, `cargo test`, and workflows pass on `main`;
   - verify Go 1.25.x availability in CI;
   - inspect govulncheck results after AWS/SSH dependency expansion.

3. **Storage/OCC design patch**
   - add explicit conditional write/precondition API to storage abstraction;
   - add tests for lost-update prevention;
   - align implementation with Phase 18.

4. **Security hardening pass**
   - redact `AgentIdentity.String()` or remove raw PII output;
   - review S3/SSH credential handling and error redaction;
   - harden DID/WebID fetches against SSRF, redirects, and private-network targets;
   - ensure logs never include tokens, DPoP proofs, secrets, private resource bodies, or policy bodies.

5. **Transport security hardening**
   - follow `docs/transport-security-reconciliation.md`;
   - add shared outbound network policy for transport endpoints;
   - harden S3 custom endpoint policy and credential-error redaction;
   - harden SSH host-key policy so production mode cannot silently accept unknown hosts;
   - update the older transport security audit only after code evidence exists.

6. **SAI clarification**
   - decide whether SAI remains deferred for enforcement or becomes a real roadmap branch;
   - document exact implemented subset;
   - add comparison/security fixtures before any authz effect.

7. **Runtime mode gating**
   - ensure `native`/`hybrid` modes cannot be enabled in production without explicit guardrails, comparison evidence, and rollback controls.

## Immediate recommended branch

Create a docs-only reconciliation branch first. The next code branch should likely be one of:

- `storage-conditional-writes-occ`
- `security-redact-agent-identity-string`
- `harden-did-resolution-network-policy`
- `transport-network-policy-hardening`
- `verify-s3-ssh-transport-security`

The best immediate next code slice is **transport network policy hardening**, because DID resolver network hardening has landed and the transport layer needs the same level of SSRF/DNS-rebinding resistance before S3/HTTP/SSH fixture distribution can be called production-ready.

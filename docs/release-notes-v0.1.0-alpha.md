# Solid Sidecar v0.1.0-alpha release documentation

**Document date:** 2026-07-07  
**Version described:** `v0.1.0-alpha`  
**Published GitHub tag/release:** not confirmed by this document  
**Readiness:** alpha development snapshot; not for production use

> This is a historical release-note document. The authoritative current implementation and production-readiness state is [`canonical-status.md`](canonical-status.md). The original notes said the `v0.1.0-alpha` tag and release branch were still “to be created,” so this document must not be treated as proof that a matching GitHub release was published.

## Purpose

The alpha documentation marked the repository’s transition from phase-numbered development toward versioned product work. It recorded substantial implementation across the gateway, authentication, authorization shadow path, storage/runtime foundations, transports, comparison tooling, SDKs, and operations.

It did **not** establish a production-ready deployment profile.

## Implementation present at the alpha snapshot

- CSS reverse-proxy gateway, request safety controls, health/readiness, rate limiting, and observability;
- issuer discovery, JWKS/JWT verification, DPoP validation and key binding, WebID identity handling;
- WAC/ACP policy discovery, parsing, evaluation, caching, and shadow comparison;
- runtime and enforcement gates with CSS fallback;
- storage abstractions, conditional operations, multiple backend foundations, quotas, tombstones, backup/restore hooks, and integrity scanning foundations;
- local, HTTP, S3, and SSH/SFTP-related transport work;
- CSS comparison, HTTP compatibility, container, CORS, and compression foundations;
- experimental DID, SAI, notification, indexing, multi-tenant, hybrid, and native-runtime work.

## Canonical readiness corrections

The original release notes used phrases such as “production-grade,” “production-ready infrastructure,” “complete,” and broad client-support claims more aggressively than the available evidence supported. The corrected status is:

- Core implementation is substantial, but the complete product is not production-ready.
- CSS remains the protocol, authorization, compatibility, and rollback authority.
- WAC/ACP evaluation remains shadow or evidence-gated, not production-authoritative.
- Native and hybrid authority remain disabled by default.
- Phase 18 storage is substantial and includes conditional/OCC-related behavior, but transaction atomicity, exhaustive quota-path verification, and production backup/restore evidence remain.
- Phase 20 conformance has substantial foundations, but the complete direct/proxy/hybrid/native matrix and public release artifacts remain incomplete.
- Phase 27 SDK work exists and has advanced significantly, but full SDK-wide package gates, browser/PWA compatibility, native secure-key adapters, Go SDK verification, and client compatibility matrices remain.
- Notifications are experimental hints, not authoritative state.
- Browser, standard Solid JavaScript client, native client, and cluster compatibility must not be marked supported without their required automated matrices.
- No external security sign-off or final production audit is claimed.

## Required operating profile

The only safe current profile described by this historical snapshot is:

```text
client
  -> solid-sidecar in CSS proxy/shadow mode
  -> CSS remains authoritative
```

Do not enable native authority or production authorization enforcement based on this document.

## Security boundaries

- `did:solid` identity never grants resource access by itself.
- SAI application registrations and grants do not bypass WAC/ACP.
- Parse and evaluator failures do not become authoritative allow decisions.
- Tokens, DPoP proofs, credentials, private keys, PKCE verifiers, private bodies, and raw policies must not be logged.
- Unsafe URLs must not become arbitrary outbound requests.
- Retries must not duplicate non-idempotent writes.
- Private resource existence and identifiers must not leak through errors, logs, metrics, caches, notifications, or indexes.

## Known alpha limitations

- production enforcement thresholds and readiness evidence are incomplete;
- native-runtime conformance, storage recovery, and rollback evidence are incomplete;
- formal conformance release artifacts are incomplete;
- browser/PWA and existing Solid JavaScript client compatibility matrices are incomplete;
- secure native DPoP key adapters and a native reference client are incomplete;
- storage atomicity, quota bypass, and failure-injection verification are incomplete;
- durable notification authorization, cursor retention, replay, backpressure, and privacy verification are incomplete;
- tenant, storage-root, cache, notification, index, and side-channel isolation suites are incomplete;
- formal threat-model, fuzzing, secret scanning, dependency/license reporting, disclosure workflow, soak testing, and external review closure remain;
- cluster support is not implemented as a production claim.

## Development track

The current engineering track is `v0.2.0-beta` preparation. No beta release is claimed until a matching tag/release and the required readiness evidence exist.

## Verification

Use the repository verification scripts and CI, but do not infer production readiness from green unit tests alone:

```sh
bash scripts/verify.sh all
bash scripts/verify.sh e2e
```

Required future release evidence is defined in [`native-pwa-production-readiness.md`](native-pwa-production-readiness.md).
# `did:solid` Method Design

This document defines the initial project-scoped design for `did:solid` in `solid-sidecar`.

`did:solid` is not currently treated as a replacement for WebID, Solid-OIDC, WAC, ACP, SAI, or CSS compatibility. It is a DID-based controller identity extension for a modern Solid runtime path. It must strengthen portability and cryptographic control without creating an authorization shortcut.

## Status

Status: design draft.

Implementation status:

- no resolver is implemented yet;
- no DID document parser is implemented yet;
- no runtime authorization behavior depends on `did:solid` yet;
- no policy engine should grant access from a DID alone.

## Scope

The scope of `did:solid` is:

- identify a Solid controller using a DID;
- bind that DID to a Solid WebID;
- bind that DID to one or more verification methods;
- advertise Solid-related service endpoints;
- support key rotation and deactivation semantics;
- allow future policy engines to reason about DID-bound identity only after explicit policy support exists.

Out of scope for the first implementation:

- replacing Solid-OIDC;
- replacing WebID;
- replacing WAC or ACP;
- blockchain anchoring by default;
- granting access directly from DID ownership;
- cross-project P2P identity semantics.

## Method name and syntax

Method name:

```text
solid
```

DID shape:

```text
did:solid:<method-specific-id>
```

The method-specific identifier must be:

- non-empty;
- ASCII-only in the first implementation;
- lowercase normalized;
- bounded in length;
- free of query strings, fragments, and path traversal semantics;
- parsed by a strict method parser.

Initial examples:

```text
did:solid:alice.example
did:solid:pod-alice-example-01
```

The implementation must reject ambiguous or unsafe identifiers before resolver work begins.

## Identity model

`did:solid` complements the canonical Solid identity model:

```text
AgentIdentity {
  webid: URI
  did: optional DID
  issuer: URI
  client_id: URI/string
  token_binding_key_thumbprint: string
  assurance_level: enum
  verification_source: enum
}
```

Rules:

- WebID remains the primary Solid agent identifier.
- Solid-OIDC remains the primary web authentication path.
- `did:solid` can raise assurance only after DID/WebID binding is verified.
- DID ownership alone must not grant resource access.
- Authorization remains policy-driven through WAC, ACP, SAI, or explicitly documented future policy semantics.

## DID document shape

A resolved `did:solid` document should be a DID document with:

- `id` equal to the DID;
- at least one verification method;
- at least one assertion or authentication relationship appropriate for the selected key type;
- a WebID service endpoint;
- a Solid storage service endpoint where applicable;
- an OIDC issuer service endpoint where applicable;
- optional notification endpoint;
- optional profile or documentation endpoint.

Example shape:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1"
  ],
  "id": "did:solid:alice.example",
  "verificationMethod": [
    {
      "id": "did:solid:alice.example#key-1",
      "type": "Multikey",
      "controller": "did:solid:alice.example",
      "publicKeyMultibase": "z..."
    }
  ],
  "authentication": [
    "did:solid:alice.example#key-1"
  ],
  "assertionMethod": [
    "did:solid:alice.example#key-1"
  ],
  "service": [
    {
      "id": "did:solid:alice.example#webid",
      "type": "SolidWebID",
      "serviceEndpoint": "https://alice.example/profile/card#me"
    },
    {
      "id": "did:solid:alice.example#storage",
      "type": "SolidStorage",
      "serviceEndpoint": "https://storage.example/alice/"
    },
    {
      "id": "did:solid:alice.example#issuer",
      "type": "SolidOIDCIssuer",
      "serviceEndpoint": "https://issuer.example/"
    }
  ]
}
```

The exact service type names are project-local until stabilized. Runtime code must treat them as explicit project semantics, not generic DID Core semantics.

## WebID binding

Binding must be bidirectional.

DID document to WebID:

- DID document includes a WebID service endpoint.
- The endpoint must be an absolute HTTPS URI.
- Fragments are allowed for WebIDs.
- Query strings should be rejected unless future compatibility evidence requires them.

WebID to DID:

- WebID profile should link back to the DID using a documented predicate.
- The predicate must be documented before implementation.
- The profile fetch must be bounded and privacy-safe.
- Missing backlink means DID binding is not trusted, but WebID-only identity can still remain valid if Solid-OIDC verification succeeded.

Initial candidate predicate:

```turtle
<#me> <https://solidproject.org/ns/did#controller> <did:solid:alice.example> .
```

This predicate is project-proposed until reviewed. Code must isolate it behind a constant and documentation.

## Verification methods

Preferred first key types:

- Ed25519 through Multikey for DID-native signatures;
- P-256 only if needed for browser/WebCrypto compatibility;
- RSA only for legacy compatibility, not as the preferred DID key type.

Rules:

- verification methods must be controlled by the DID;
- key material must be public only;
- private key material must never be logged;
- unsupported key types fail closed for DID binding;
- key IDs must be fragment-only under the DID document where possible.

## Resolution model

The first resolver should be explicit and conservative.

Resolver inputs:

- DID string;
- resolver configuration;
- timeout;
- maximum document size;
- allowed source policy.

Resolver outputs:

- parsed DID;
- normalized DID document;
- service endpoints;
- verification methods;
- expiration/cache metadata;
- validation warnings;
- failure reason.

Initial source policy options:

```yaml
did_solid:
  enabled: false
  allowed_resolvers:
    - local
    - https
  max_document_bytes: 65536
  cache_ttl_seconds: 300
```

The resolver must not perform arbitrary unbounded network fetches.

## DID-to-document discovery

The project must choose one of these before resolver implementation:

1. explicit local registry mapping DID to DID document URL;
2. HTTPS well-known mapping from method-specific ID;
3. Solid storage description mapping;
4. other reviewed deterministic mapping.

Initial safest path:

- local registry for tests;
- explicit HTTPS resolver configuration for staging;
- no global network discovery by default.

## Update and rotation

Key rotation must be explicit and auditable.

Required behavior:

- new DID document must preserve DID `id`;
- old and new verification methods must be represented with enough metadata to validate transition where possible;
- resolver cache must not hide rotation beyond bounded TTL;
- stale keys must not remain valid for new assertions after revocation/deactivation metadata is observed;
- rotation events must be logged without key material or private identity leakage.

## Deactivation

A deactivated `did:solid` must fail DID binding.

Rules:

- deactivation must not delete WebID identity;
- WebID-only Solid-OIDC behavior may continue if independently valid;
- deactivated DID must not be used to raise assurance;
- cached active documents must be invalidated when deactivation is detected.

## Runtime integration phases

### Phase A: design only

- Add this document.
- Add syntax examples.
- Add test vector plan.

### Phase B: parser and test vectors

- strict DID parser;
- valid/invalid DID vectors;
- method-specific-id normalization tests;
- no network access.

### Phase C: local resolver

- local fixture registry;
- DID document parser;
- service endpoint validation;
- verification method validation;
- WebID service extraction.

### Phase D: WebID backlink validation

- bounded WebID profile fetch;
- RDF parser boundary integration;
- documented backlink predicate;
- DID/WebID bidirectional validation.

### Phase E: authn identity binding

- optional DID binding on verified WebID identities;
- assurance-level calculation;
- no authz effect by default;
- metrics for DID binding success/failure without identity labels.

### Phase F: policy-aware DID references

Only after explicit policy semantics exist:

- WAC/ACP extension decision;
- fixtures for DID-referenced policy;
- CSS compatibility and fallback behavior;
- no enforcement until mismatch rate is measured.

## Security considerations

Threats:

- DID/WebID substitution;
- resolver SSRF;
- cache poisoning;
- malicious DID documents;
- key confusion;
- downgrade from strong WebID/OIDC verification to weak DID assertion;
- unauthorized identity correlation;
- stale key use after rotation;
- deactivation bypass.

Controls:

- explicit resolver allowlist;
- strict DID syntax parser;
- HTTPS-only remote endpoints unless local fixtures are used;
- bounded document size;
- bounded fetch timeout;
- safe content-type handling;
- copy-safe caches;
- bidirectional DID/WebID binding;
- no DID-only authorization;
- privacy-safe metrics and logs.

## Privacy considerations

`did:solid` can increase correlation risk because a persistent DID may link identities, storage locations, issuers, and keys.

Initial privacy rules:

- do not include raw DIDs in aggregate metrics labels;
- hash or omit DID values in logs unless debug mode is explicitly enabled in local development;
- do not expose DID binding status to unauthorized parties;
- do not fetch DID documents or WebID backlinks for arbitrary attacker-supplied DIDs unless resolver policy permits it;
- document correlation risk before enabling DID binding by default.

## Interoperability limits

Until reviewed and adopted beyond this repository, `did:solid` is project-defined.

Therefore:

- external clients must not be required to use it;
- WebID-only clients must keep working;
- CSS compatibility must remain intact;
- Solid protocol conformance must not depend on DID support;
- deployments must be able to disable DID support entirely.

## Acceptance criteria before implementation proceeds

- DID syntax and test vectors are documented.
- WebID backlink predicate is reviewed and documented.
- resolver source policy is explicit.
- security and privacy risks are added to the threat model.
- runtime integration plan states clearly that DID binding does not grant access by itself.

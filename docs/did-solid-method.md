# did:solid Method Design

This document defines the initial `did:solid` design direction for `solid-sidecar`.

`did:solid` is a project-defined Solid-oriented DID method extension. It is not treated as a replacement for WebID, Solid-OIDC, WAC, ACP, or CSS compatibility. Until a broader standards process adopts compatible semantics, this repository must document `did:solid` as an experimental interoperability layer with explicit feature gates.

## Goals

`did:solid` should provide:

- portable controller identity for Solid agents;
- cryptographic key discovery and rotation that can be linked to a Solid WebID;
- service endpoint discovery for Solid storage, WebID, OIDC issuer, and notifications;
- a foundation for future DID-aware authorization policies without granting access by DID alone;
- testable, deterministic resolver behavior suitable for Go/Rust runtime integration.

## Non-goals

`did:solid` must not:

- replace WebID as the primary Solid agent identifier in this repository's compatibility path;
- bypass Solid-OIDC;
- bypass WAC, ACP, SAI, or CSS authorization behavior;
- imply that a DID controller has access to a resource without explicit policy;
- require a blockchain or ledger by default;
- leak private Solid storage locations through public DID documents unless the user/operator explicitly opts in;
- make existing Solid clients incompatible.

## Compatibility rule

The identity model remains:

```text
Solid-OIDC verified token + DPoP binding -> trusted WebID identity
trusted WebID identity + optional did:solid binding -> enriched AgentIdentity
AgentIdentity + WAC/ACP/SAI policy -> authorization decision
```

A valid DID document proves only DID controller information. It does not prove authorization to a Solid resource.

## Method syntax

Initial syntax:

```text
did:solid:<method-specific-id>
```

The method-specific identifier must be:

- ASCII;
- lowercase-normalized where possible;
- URL-safe;
- bounded in length;
- unambiguous after percent-decoding rules are applied;
- rejected if it contains path traversal, control characters, query strings, fragments, or reserved delimiters not explicitly allowed by the final method grammar.

A future version may define method-specific variants, for example:

```text
did:solid:web:<host-scoped-id>
did:solid:pod:<storage-scoped-id>
```

Do not implement variants until the grammar and resolver behavior are documented with test vectors.

## DID document requirements

A `did:solid` DID document should include:

- `id` equal to the DID being resolved;
- at least one verification method;
- authentication relationship referencing a verification method;
- assertion method relationship when profile assertions are supported;
- service endpoint for the Solid WebID;
- service endpoint for the Solid storage or storage description;
- service endpoint for the Solid-OIDC issuer;
- optional service endpoint for Solid notifications;
- optional service endpoint for a public profile or documentation resource.

Example shape:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1"
  ],
  "id": "did:solid:example-alice",
  "verificationMethod": [
    {
      "id": "did:solid:example-alice#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:solid:example-alice",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "..."
      }
    }
  ],
  "authentication": [
    "did:solid:example-alice#key-1"
  ],
  "assertionMethod": [
    "did:solid:example-alice#key-1"
  ],
  "service": [
    {
      "id": "did:solid:example-alice#webid",
      "type": "SolidWebID",
      "serviceEndpoint": "https://alice.example/profile/card#me"
    },
    {
      "id": "did:solid:example-alice#storage",
      "type": "SolidStorage",
      "serviceEndpoint": "https://alice.example/"
    },
    {
      "id": "did:solid:example-alice#issuer",
      "type": "SolidOIDCIssuer",
      "serviceEndpoint": "https://issuer.example/"
    }
  ]
}
```

The exact context, service type names, verification method types, and endpoint constraints must be finalized before implementation.

## Key material

Preferred verification method support:

- Ed25519 for deterministic modern signatures;
- P-256 as an optional compatibility key type for browser/WebCrypto and platform keychain integrations;
- RSA only if required for compatibility, not as the preferred new-key path.

Rules:

- private keys are never stored in the sidecar;
- resolver validates only public verification material;
- minimum key strength must be enforced;
- unsupported key types fail closed for DID authentication;
- old keys must remain discoverable for a bounded rotation window only when explicitly documented.

## DID to WebID binding

A DID document may claim a WebID service endpoint. That claim is not sufficient by itself.

A trusted binding requires:

1. DID document lists the WebID service endpoint.
2. WebID profile links back to the DID.
3. The WebID profile is retrieved through a bounded, safe fetch path.
4. The WebID profile relationship uses a documented predicate.
5. The Solid-OIDC trusted issuer relationship remains valid where authn depends on Solid-OIDC.

Candidate WebID backlink predicate must be documented before implementation. Until then, use fixtures only and do not enforce DID/WebID binding in production.

## WebID to DID binding

The WebID profile should be able to advertise a controller DID.

Candidate shape:

```turtle
<#me> <https://solidproject.org/ns/solid/terms#controllerDid> <did:solid:example-alice> .
```

The predicate above is a placeholder for project documentation. Do not treat it as standardized until the project finalizes the vocabulary decision.

Rules:

- preserve WebID fragment identifiers;
- reject backlink mismatch;
- reject multiple conflicting controller DIDs unless a future multi-controller model is explicitly designed;
- do not log full WebIDs or DID documents in normal request logs.

## Resolution model

The initial resolver should be conservative.

Possible resolution sources:

- explicit local resolver map for tests;
- configured HTTPS resolver endpoint;
- Solid storage description link;
- WebID profile backlink;
- operator-configured resolver base.

Initial implementation should start with test/local and explicitly configured HTTPS resolution only. Do not perform arbitrary network discovery from attacker-controlled DIDs.

Resolver steps:

1. Parse and validate DID syntax.
2. Check local/test resolver map.
3. If configured, resolve through allowed resolver endpoint.
4. Fetch with bounded timeout and size.
5. Require JSON DID document content type where available.
6. Validate DID document `id` equals requested DID.
7. Validate verification methods.
8. Extract service endpoints.
9. Optionally validate WebID backlink.
10. Return a copy-safe resolved document structure.

Acceptance criteria:

- arbitrary DID strings cannot trigger arbitrary SSRF;
- resolver has timeout and response-size limits;
- invalid documents fail closed;
- successful resolution returns copy-safe structures;
- resolver errors are privacy-safe.

## Update and rotation model

The method must document update and key rotation before production use.

Minimum requirements:

- old key -> new key rotation proof, or authoritative update through the configured resolver source;
- bounded overlap window for old and new keys;
- revocation/deactivation semantics;
- audit-safe rotation logs;
- cache invalidation on rotation.

Rules:

- key rotation cannot silently change the bound WebID;
- WebID change requires explicit evidence and should be treated as a high-risk identity transition;
- stale DID document cache entries must not preserve removed keys beyond configured bounds.

## Deactivation model

A deactivated DID must fail closed for DID binding.

Rules:

- deactivation does not delete historical audit references;
- deactivation must not remove the ability to explain old decisions using historical metadata hashes;
- deactivation must not revoke WebID identity by itself unless Solid-OIDC/WebID verification also fails.

## AgentIdentity integration

`did:solid` should flow into the canonical identity model as optional enrichment:

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

- WebID-only identity remains valid;
- DID-enhanced identity has a higher identity-assurance annotation only when the DID/WebID binding is verified;
- DID binding failures degrade to WebID-only behavior unless config requires DID;
- authz must not grant additional access based on DID until policy semantics support DID references.

## Authorization interaction

Initial rule:

```text
DID does not authorize. Policy authorizes.
```

Future policy work may support DID references only after:

- WAC/ACP DID reference semantics are documented;
- parser fixtures exist;
- evaluator fixtures exist;
- CSS compatibility or project-specific divergence is explicitly documented;
- enforcement gates understand DID identity assurance.

Do not add DID matching to WAC/ACP evaluators as an implicit alias for WebID.

## Privacy considerations

DID documents can make relationships more discoverable. This is useful for portability but risky for privacy.

Risks:

- public correlation between DID, WebID, storage, issuer, and notification endpoint;
- long-lived identifiers linking activity across services;
- cache retention after DID rotation/deactivation;
- resolver logs exposing user identity graphs.

Mitigations:

- make public service endpoints minimal by default;
- allow private or pairwise DID strategies in future docs;
- keep resolver logs aggregate and privacy-safe;
- avoid resource paths in DID service endpoints unless explicitly intended;
- bound resolver cache TTLs;
- document user-visible consequences of publishing a DID document.

## Security considerations

Threats:

- DID document spoofing;
- resolver SSRF;
- key substitution;
- downgrade to weaker keys;
- stale key acceptance;
- WebID backlink spoofing;
- conflicting DID/WebID bindings;
- authorization confusion where DID is mistaken for access grant.

Required mitigations:

- strict resolver allowlist/config;
- bounded fetches;
- exact DID `id` match;
- supported key type validation;
- minimum key strength;
- backlink verification;
- cache invalidation;
- no authorization shortcut;
- privacy-safe audit hashes.

## Implementation phases

### Phase D1: design finalization

- finalize method grammar;
- finalize service endpoint vocabulary;
- finalize WebID backlink predicate;
- define resolver source policy;
- define update/rotation/deactivation semantics;
- add test vectors.

### Phase D2: parser and test vectors

- implement DID syntax parser in Go;
- add negative parser tests;
- add positive parser tests;
- add canonical string normalization tests.

### Phase D3: local/test resolver

- implement static resolver map for tests;
- validate DID document shape;
- validate verification methods;
- validate service endpoints;
- expose copy-safe resolved document objects.

### Phase D4: configured HTTPS resolver

- add resolver config;
- add bounded HTTP fetches;
- add content-type checks;
- add response-size limits;
- add resolver cache;
- add SSRF protections.

### Phase D5: WebID backlink validation

- fetch WebID profile through bounded policy;
- parse backlink predicate;
- verify DID/WebID agreement;
- handle conflicts;
- preserve privacy-safe logs.

### Phase D6: AgentIdentity integration

- attach verified DID to trusted identity only after WebID binding succeeds;
- add assurance-level annotation;
- ensure authz request builder can carry DID without using it for access decisions.

### Phase D7: future policy integration decision

- decide whether WAC/ACP/SAI should support DID references;
- document semantics;
- add parser/evaluator fixtures before any implementation;
- keep enforcement gated.

## Stop conditions

Pause `did:solid` implementation if:

- method syntax is ambiguous;
- resolver can be tricked into arbitrary network fetches;
- WebID backlink predicate is not finalized;
- DID binding would grant access without explicit policy;
- key rotation semantics are unclear;
- public DID documents would leak private storage topology by default;
- existing WebID/Solid-OIDC clients would break.

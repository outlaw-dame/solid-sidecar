# Compression Compatibility Plan

This document defines how `solid-sidecar` should add Gzip and Zstd support without breaking Solid compatibility, CSS pass-through behavior, HTTP semantics, cache correctness, range requests, or existing clients.

Compression is a performance feature, not a protocol authority feature. It must be negotiated, reversible, testable, and safe to disable.

## Goals

- Support response compression for compatible clients.
- Add Gzip first because it has the broadest client/intermediary compatibility.
- Add Zstd behind explicit configuration because support is newer and less universal.
- Preserve Solid/CSS semantics for clients that do not request compression.
- Avoid corrupting ETags, `Content-Length`, `Content-Encoding`, range requests, streaming bodies, or cached variants.
- Keep authorization, identity, policy parsing, and audit behavior independent of compression.

## Non-goals

- Do not require clients to support compression.
- Do not compress request bodies by default.
- Do not change RDF, WAC, ACP, or Solid-OIDC semantics.
- Do not use compression as an authorization or privacy mechanism.
- Do not force Zstd for all clients.
- Do not dynamically compress responses when doing so would make range handling, signatures, checksums, or validators ambiguous.

## Compatibility rule

The sidecar must preserve identity-compatible behavior unless the client explicitly negotiates compression.

Default behavior:

```text
Client sends no Accept-Encoding -> sidecar returns identity-compatible response.
Client sends Accept-Encoding: gzip -> sidecar may return gzip if enabled and safe.
Client sends Accept-Encoding: zstd -> sidecar may return zstd only if enabled and safe.
Client sends Accept-Encoding: br, gzip -> sidecar may return gzip if enabled and safe; Brotli is not in scope yet.
Client sends Accept-Encoding: identity;q=0 and no supported encoding -> sidecar returns 406 or proxies CSS behavior according to configured compatibility mode.
```

## Phase C1: Compression architecture and config

Implement configuration first:

```yaml
compression:
  enabled: false
  response:
    gzip:
      enabled: true
      min_bytes: 1024
      level: default
    zstd:
      enabled: false
      min_bytes: 1024
      level: default
    skip_content_types:
      - image/
      - audio/
      - video/
      - application/zip
      - application/gzip
      - application/zstd
      - application/pdf
    skip_sensitive_responses: true
    skip_range_requests: true
  request:
    decompression_enabled: false
    gzip_enabled: false
    zstd_enabled: false
    max_decompressed_bytes: 10485760
```

Rules:

- compression is globally disabled by default until tests exist;
- Gzip can be enabled before Zstd;
- Zstd must stay behind explicit config;
- request decompression must stay disabled by default;
- every configurable limit needs validation and documentation.

Acceptance criteria:

- invalid compression config fails startup;
- compression can be disabled without code changes;
- default config preserves current pass-through behavior.

## Phase C2: Response Gzip negotiation

Implement:

- parse `Accept-Encoding` with quality values;
- select Gzip only when accepted and enabled;
- skip compression for small responses;
- skip compression for already-compressed media;
- skip compression for streaming responses unless explicitly supported;
- set `Content-Encoding: gzip` only when actually compressed;
- add/merge `Vary: Accept-Encoding` when response variants differ;
- remove or recompute `Content-Length` correctly;
- preserve `Content-Type`;
- preserve status code;
- keep `HEAD` semantics correct.

Acceptance criteria:

- clients without `Accept-Encoding: gzip` receive identity-compatible responses;
- `Vary: Accept-Encoding` is present when compression changes representation;
- `Content-Length` is never stale after compression;
- `HEAD` does not return an incorrect body or incompatible metadata;
- CSS direct vs sidecar fixtures prove status and safe headers remain compatible.

## Phase C3: Range and validator safety

Dynamic compression changes bytes on the wire, so range and validator behavior must be conservative.

Implement:

- skip dynamic compression for requests with `Range` by default;
- preserve CSS range behavior unchanged when skipping compression;
- do not emit a strong ETag for dynamically compressed bytes unless it identifies that compressed variant;
- prefer preserving CSS validators only for identity-compatible pass-through;
- document weak validator behavior if used;
- ensure `If-None-Match`, `If-Modified-Since`, and conditional requests are not broken by variant handling.

Acceptance criteria:

- range responses are not dynamically recompressed by default;
- `206 Partial Content` responses remain CSS-compatible;
- compressed and identity variants cannot share unsafe strong validators;
- conditional requests have explicit fixture coverage.

## Phase C4: Zstd response negotiation

Implement Zstd after Gzip behavior is stable.

Rules:

- Zstd is disabled by default;
- Zstd requires explicit config;
- Zstd is selected only when `Accept-Encoding` advertises `zstd` with acceptable quality;
- Gzip remains available as the compatibility fallback where both are accepted;
- identity remains available unless the client rejects it;
- Zstd compression level must be bounded;
- memory usage must be bounded;
- high-cardinality metrics must not include resource paths or WebIDs.

Acceptance criteria:

- Zstd clients receive `Content-Encoding: zstd` only when enabled and negotiated;
- clients that do not advertise Zstd are unaffected;
- Gzip behavior does not regress;
- cache variants distinguish identity, gzip, and zstd;
- Zstd can be disabled instantly by config.

## Phase C5: Request decompression

Request decompression is higher risk because it changes inbound body handling and can amplify resource use.

Default: disabled.

Implement only after response compression is stable:

- optional request decompression for `Content-Encoding: gzip`;
- optional request decompression for `Content-Encoding: zstd`;
- decompressed byte limit;
- compression-ratio guard;
- timeout/cancellation support;
- body-size accounting after decompression;
- clear error taxonomy for unsupported encodings, invalid compressed streams, decompressed-size limit exceeded, and timeout;
- no request-body logging.

Acceptance criteria:

- compressed request bodies are rejected unless explicitly enabled;
- decompressed bodies remain subject to normal Solid request validation;
- decompression bombs are rejected before unbounded memory use;
- CSS receives a body representation consistent with compatibility mode.

## Phase C6: Cache and proxy correctness

Implement:

- variant-aware response cache metadata;
- cache key includes accepted/chosen content encoding when compression is applied;
- `Vary: Accept-Encoding` preservation/merge logic;
- no sharing compressed variants with identity variants;
- no compression across authenticated/private response boundaries unless explicitly reviewed;
- cache poisoning tests.

Acceptance criteria:

- identity/gzip/zstd variants cannot cross-contaminate;
- private responses are not accidentally cached or shared because of compression;
- `Vary` behavior is deterministic and covered by tests.

## Phase C7: Observability and controls

Implement metrics without identifiers:

- compression enabled/disabled state;
- selected encoding count: identity/gzip/zstd;
- skipped compression reason counts;
- compression errors;
- decompression rejections;
- compressed bytes in/out totals;
- compression latency buckets;
- memory guard rejections.

Controls:

- disable all compression;
- disable Zstd independently;
- disable request decompression independently;
- raise/lower min response size;
- disable compression for content-type prefixes;
- emergency bypass to identity pass-through.

Acceptance criteria:

- operator can prove whether compression is active;
- operator can disable Zstd without disabling Gzip;
- operator can restore identity pass-through without redeploying.

## Test matrix

Minimum fixtures:

| Case | Expected behavior |
| --- | --- |
| no `Accept-Encoding` | identity-compatible response |
| `Accept-Encoding: gzip` | gzip only if enabled and safe |
| `Accept-Encoding: zstd` | zstd only if enabled and safe |
| `Accept-Encoding: gzip, zstd` | configured preference, safe variant only |
| `Accept-Encoding: identity;q=0` | supported encoding or explicit 406/compat behavior |
| small text response | identity unless threshold disabled |
| Turtle/RDF text response | compressible when accepted and safe |
| image/audio/video response | skipped |
| already gzip/zstd response | skipped |
| `HEAD` | correct headers, no body |
| `Range` | skip dynamic compression by default |
| `206 Partial Content` | CSS-compatible pass-through |
| conditional GET | validators remain correct |
| private/authenticated response | no unsafe shared cache behavior |
| malformed compressed request | bounded rejection if request decompression enabled |
| decompression bomb | bounded rejection |

## Implementation order

1. Config schema and validation.
2. Negotiation parser tests.
3. Response Gzip middleware in disabled-by-default mode.
4. Gzip pass-through/comparison fixtures.
5. Range, ETag, and `Vary` safety fixtures.
6. Zstd middleware behind explicit config.
7. Variant-aware cache metadata.
8. Request decompression feature gates.
9. Observability and emergency controls.
10. Staging runbook update.

## Stop conditions

Pause compression work if any of these occur:

- compressed response changes Solid-visible semantics unexpectedly;
- range requests break;
- `HEAD` metadata is wrong;
- validators are ambiguous or unsafe;
- cache variants cross-contaminate;
- Zstd support breaks older clients or intermediaries;
- compression creates request-path memory pressure;
- request decompression cannot be bounded safely;
- logs expose resource bodies, tokens, DPoP proofs, or policy bodies.

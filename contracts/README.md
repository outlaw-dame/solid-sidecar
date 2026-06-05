# Authorization Contracts

The files in this directory define the JSON boundary between the Go sidecar and deterministic policy kernels.

## Request contracts

`authz_request.schema.json` describes well-formed `authz.v1` authorization requests. A valid request must use:

- schema version `authz.v1`
- a visible-ASCII `request_id` with no spaces or control characters
- a supported HTTP method
- an HTTP(S) resource URI without fragments, backslashes, or control characters
- at least one requested access mode
- non-negative `now_unix`

The invalid request fixtures under `contracts/fixtures/` intentionally violate one of these constraints to lock deterministic shadow-deny behavior. They are not expected to validate against `authz_request.schema.json`.

## Decision contracts

`authz_decision.schema.json` describes valid sidecar/kernel decisions. Even when a request is invalid, the expected decision fixture must remain a valid `authz.v1` decision. For malformed request IDs, the decision uses `invalid-request-<request_hash_prefix>` instead of echoing malformed input.

Both Go and Rust tests read the same fixture files to prevent contract drift.

# Authorization Contract Fixtures

These fixtures lock the `authz.v1` JSON boundary shared by the Go sidecar and the Rust policy kernel.

- `authz_manifest.json` is the shared fixture manifest consumed by Go and Rust tests.
- `../authz_fixture_manifest.schema.json` defines the manifest shape and filename constraints.
- `authz_request.valid.json` is a valid authorization request contract.
- `authz_decision.shadow.json` is the expected shadow-mode decision for that request.
- `authz_request.unsupported_schema.json` and `authz_decision.unsupported_schema.json` lock unsupported-schema denial behavior.
- `authz_request.invalid_request_id.json` and `authz_decision.invalid_request_id.json` lock malformed-request-ID denial behavior using a deterministic valid surrogate request ID in the decision.
- `authz_request.unsupported_method.json` and `authz_decision.unsupported_method.json` lock unsupported-method denial behavior.
- `authz_request.missing_modes.json` and `authz_decision.missing_modes.json` lock missing-mode denial behavior.
- `authz_request.unsafe_uri.json` and `authz_decision.unsafe_uri.json` lock unsafe-resource-URI denial behavior.

Both Go and Rust tests read `authz_manifest.json`. Changes to request or decision fixture files must also update the manifest and should be reviewed carefully. Go and Rust tests both audit the fixture directory so orphan `authz_request.*.json` and `authz_decision.*.json` files fail fast. Go and Rust tests also validate manifest schema version, duplicate entries, local fixture filename prefixes, and path-separator rejection.

Current guarantees:

1. Valid shadow-mode requests produce `decision: "abstain"`.
2. Invalid shadow-mode requests produce deterministic structured deny decisions.
3. Malformed request IDs are replaced in decisions with `invalid-request-<request_hash_prefix>` so the decision remains a valid `authz.v1` contract while retaining privacy-safe correlation.
4. `abstain` remains non-enforcing and must continue to CSS.
5. `request_hash` and `policy_hash` are deterministic audit correlation fields.
6. Fixture changes should be accompanied by manifest updates and matching Go/Rust fixture expectations.

These fixtures are not production policy examples.

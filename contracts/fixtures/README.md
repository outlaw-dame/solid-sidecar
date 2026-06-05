# Authorization Contract Fixtures

These fixtures lock the `authz.v1` JSON boundary shared by the Go sidecar and the Rust policy kernel.

- `authz_request.valid.json` is a valid authorization request contract.
- `authz_decision.shadow.json` is the expected shadow-mode decision for that request.
- `authz_request.unsupported_schema.json` and `authz_decision.unsupported_schema.json` lock unsupported-schema denial behavior.
- `authz_request.unsupported_method.json` and `authz_decision.unsupported_method.json` lock unsupported-method denial behavior.
- `authz_request.missing_modes.json` and `authz_decision.missing_modes.json` lock missing-mode denial behavior.
- `authz_request.unsafe_uri.json` and `authz_decision.unsafe_uri.json` lock unsafe-resource-URI denial behavior.

Both Go and Rust tests should read these same files. Changes to any fixture must be treated as contract changes and reviewed carefully.

Current guarantees:

1. Valid shadow-mode requests produce `decision: "abstain"`.
2. Invalid shadow-mode requests produce deterministic structured deny decisions when the expected decision itself can remain a valid `authz.v1` contract.
3. `abstain` remains non-enforcing and must continue to CSS.
4. `request_hash` and `policy_hash` are deterministic audit correlation fields.
5. Fixture changes should be accompanied by matching Go and Rust tests.

Malformed request-ID behavior is intentionally not fixture-locked yet because the current evaluators echo the malformed request ID into the decision for correlation, which makes the expected decision unsuitable as a valid contract fixture. That behavior should be resolved in a dedicated design pass before fixture-locking.

These fixtures are not production policy examples. They do not implement WAC, ACP, SAI, RDF parsing, or issuer/WebID policy decisions.

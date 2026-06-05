# Authorization Contract Fixtures

These fixtures lock the `authz.v1` JSON boundary shared by the Go sidecar and the Rust policy kernel.

- `authz_request.valid.json` is a valid authorization request contract.
- `authz_decision.shadow.json` is the expected shadow-mode decision for that request.

Both Go and Rust tests should read these same files. Changes to either fixture must be treated as contract changes and reviewed carefully.

Current guarantees:

1. Valid shadow-mode requests produce `decision: "abstain"`.
2. `abstain` remains non-enforcing and must continue to CSS.
3. `request_hash` and `policy_hash` are deterministic audit correlation fields.
4. Fixture changes should be accompanied by matching Go and Rust tests.

These fixtures are not production policy examples. They do not implement WAC, ACP, SAI, RDF parsing, or issuer/WebID policy decisions.

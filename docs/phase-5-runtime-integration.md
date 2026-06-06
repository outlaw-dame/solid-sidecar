# Phase 5 Runtime Integration Groundwork

Phase 5 begins the runtime integration path for the Rust policy-kernel seam. This phase remains shadow-only and non-enforcing. Community Solid Server remains the production Solid authorization authority.

## Goals

Phase 5 adds a controlled local evaluator option so the Go sidecar can send `authz.v1` request JSON to a trusted local policy-kernel command and decode an `authz.v1` decision JSON response.

Current goals:

1. Keep local Go shadow evaluation as the default.
2. Add an explicit `external_cli` evaluator mode for local policy-kernel integration.
3. Pass command arguments as argv values, not as an interpolated command string.
4. Apply strict per-request timeout and output-size bounds.
5. Validate every returned decision before normal shadow logging.
6. Fail open to CSS on evaluator errors because shadow authz is observational only.
7. Keep warning logs privacy-safe through stable reason labels rather than raw tool output.

## Configuration

Authz shadow mode remains disabled by default.

```yaml
authz:
  shadow_enabled: false
  public_base_url: ""
  evaluator: "local"
  external_command: ""
  external_args: ""
  external_timeout: "2s"
  external_max_output_bytes: 65536
```

Supported evaluators:

- `local`: use the Go shadow evaluator. This is the default.
- `external_cli`: send the request contract to a trusted local command and decode the decision response.

`external_cli` requires `shadow_enabled: true` and `external_command` to be configured. Arguments are configured separately through `external_args`.

## Security and privacy boundaries

The external evaluator boundary is intentionally narrow:

- input receives only the `authz.v1` request JSON built by the sidecar;
- output is bounded and must contain exactly one valid `authz.v1` decision JSON object;
- diagnostic output is bounded and is not logged verbatim;
- runtime is bounded by `authz.external_timeout`;
- output size is bounded by `authz.external_max_output_bytes`;
- decision JSON is decoded with unknown-field and trailing-data rejection;
- invalid, oversized, timed-out, or failed evaluator calls remain non-enforcing and pass through to CSS.

## Non-goals

Phase 5 does not authorize Solid access. It does not implement WAC, ACP, SAI, RDF parsing, issuer/WebID policy decisions, decision caching, or production enforcement.

## Verification

Run the normal verification entrypoint:

```sh
bash scripts/verify.sh all
```

Focused Go checks should cover:

- external evaluator config validation;
- bounded output behavior;
- gateway evaluator selection;
- existing middleware non-enforcement and privacy-safe logging behavior.

## Handoff criteria for later enforcement work

A later enforcement phase must add policy semantics and rollout gates before any decision can block CSS. Required future work includes:

- WAC/ACP/SAI golden fixtures;
- issuer/WebID identity decision rules;
- deterministic policy loading and versioning;
- decision cache semantics and invalidation;
- failure-mode policy;
- metrics and alerting;
- staged rollout controls;
- explicit tests proving enforcement cannot be enabled accidentally.

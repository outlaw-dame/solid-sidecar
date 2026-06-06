# Phase 5 Runtime Integration Groundwork

Phase 5 begins the runtime integration path for the Rust policy-kernel seam. This phase remains shadow-only and non-enforcing. Community Solid Server remains the production Solid authorization authority.

## Goals

Phase 5 adds a controlled evaluator option so the Go sidecar can exchange `authz.v1` request and decision JSON with a trusted local policy-kernel component.

Current goals:

1. Keep local Go shadow evaluation as the default.
2. Add an explicit `external_cli` evaluator mode for local policy-kernel integration.
3. Keep evaluator arguments separate from the evaluator path.
4. Apply strict per-request timeout and output-size bounds.
5. Validate every returned decision before normal shadow logging.
6. Fail open to CSS on evaluator errors because shadow authz is observational only.
7. Use the local Go shadow evaluator as an observability fallback when `external_cli` fails.
8. Apply bounded exponential backoff after external evaluator failures so repeated failures do not cause repeated external attempts on every request.
9. Keep warning logs privacy-safe through stable reason labels rather than raw diagnostic output.

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
- `external_cli`: use the configured local policy-kernel evaluator boundary.

`external_cli` requires `shadow_enabled: true` and `external_command` to be configured. Arguments are configured separately through `external_args`. When `external_cli` fails or returns invalid output, the sidecar logs a privacy-safe warning, applies bounded backoff before the next external attempt, and attempts local shadow evaluation so contract observability is preserved without blocking CSS.

## Security and privacy boundaries

The external evaluator boundary is intentionally narrow:

- input receives only the `authz.v1` request JSON built by the sidecar;
- output is bounded and must contain exactly one valid `authz.v1` decision JSON object;
- diagnostic output is bounded and is not logged verbatim;
- runtime is bounded by `authz.external_timeout`;
- output size is bounded by `authz.external_max_output_bytes`;
- repeated failures are rate-limited by a bounded backoff wrapper;
- decision JSON is decoded with unknown-field and trailing-data rejection;
- invalid, oversized, timed-out, or failed evaluator calls remain non-enforcing and pass through to CSS;
- local fallback decisions are also validated before normal shadow logging.

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
- backoff behavior after evaluator failures;
- gateway evaluator selection;
- local fallback selection for external evaluator mode;
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

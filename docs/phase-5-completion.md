# Phase 5 Completion: Runtime Integration Groundwork

Phase 5 is complete when the Go sidecar has a safe, opt-in runtime evaluator seam for authz shadow observation without changing production authorization behavior. Community Solid Server remains the Solid protocol and authorization authority.

## Completed scope

Phase 5 completed the following work:

1. `authz.evaluator` supports `local` and `external_cli` modes.
2. `local` remains the default evaluator.
3. `external_cli` is opt-in and only relevant when authz shadow mode is enabled.
4. External evaluator configuration includes command, args, timeout, and output-size bounds.
5. External evaluator configuration is validated before startup.
6. The external evaluator receives bounded `authz.v1` request input and returns bounded `authz.v1` decision output.
7. Returned decisions are decoded and validated before normal shadow logging.
8. External evaluator failures remain non-enforcing and pass through to CSS.
9. External evaluator failures fall back to local shadow evaluation for observability.
10. Repeated external evaluator failures are guarded by bounded backoff.
11. Warning logs remain privacy-safe and do not include raw diagnostic output.
12. README, example config, and Phase 5 runtime docs describe the active integration contract.

## Phase 5 guarantees

- CSS remains authoritative.
- Authz shadow evaluation remains non-enforcing.
- `local` evaluator behavior is unchanged by default.
- `external_cli` must be explicitly configured.
- External evaluator output is bounded and must decode as a valid decision contract.
- External evaluator errors, invalid decisions, timeouts, and backoff skips do not block requests.
- Local fallback preserves shadow observability when external evaluation fails.

## Phase 5 non-goals

Phase 5 does not implement WAC, ACP, SAI, RDF parsing, issuer/WebID policy decisions, decision caching, or production enforcement.

## Verification

Run:

```sh
bash scripts/verify.sh all
```

Relevant checks include:

- external evaluator config validation;
- bounded output behavior;
- backoff behavior after evaluator failures;
- gateway evaluator selection;
- local fallback selection for external evaluator mode;
- middleware non-enforcement and privacy-safe logging behavior.

## Handoff to Phase 6

Phase 6 starts runtime observability hardening. It should expose privacy-safe counters and snapshots for authz shadow behavior without adding user identifiers, resource identifiers, query strings, raw evaluator errors, or production enforcement.

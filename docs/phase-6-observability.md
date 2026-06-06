# Phase 6 Completion: Authz Shadow Observability Metrics

Phase 6 is complete when authz shadow behavior has privacy-safe in-process metrics that help operators understand evaluator health without exposing users, resources, tokens, query strings, raw errors, WebIDs, or client IDs.

## Completed scope

Phase 6 completed the following work:

1. Added a thread-safe `ShadowMetrics` recorder.
2. Added structured metric keys for authz shadow events.
3. Added immutable metric snapshots for safe reads.
4. Recorded successful primary shadow decisions.
5. Recorded privacy-safe warning reasons for request-build, evaluator, invalid-decision, and fallback failures.
6. Recorded successful fallback decisions separately from primary decisions.
7. Wired metrics into the gateway when authz shadow mode is enabled.
8. Kept metrics disabled when authz shadow mode is disabled.
9. Added tests for concurrency, snapshot immutability, middleware event recording, fallback event recording, and gateway wiring.

## Metric model

The metric key contains only low-cardinality fields:

- `event`
- `decision`
- `reason_code`
- `error_reason`

The metric key intentionally does not include:

- request ID;
- method;
- path;
- query string;
- resource URI;
- WebID;
- client ID;
- issuer;
- origin;
- raw evaluator errors;
- raw diagnostic output;
- audit hashes.

## Events

Current event names:

- `decision`: primary evaluator returned a valid decision.
- `warning`: middleware observed a privacy-safe warning condition.
- `fallback_decision`: fallback evaluator returned a valid decision.
- `fallback_failure`: fallback evaluator failed or returned an invalid decision.

## Guarantees

- Metrics are in-process only in this phase.
- Metrics do not create a public endpoint yet.
- Metrics do not affect request handling.
- Metrics do not authorize Solid access.
- Metrics do not block CSS.
- Metrics remain safe to use with external evaluator backoff and local fallback behavior.

## Non-goals

Phase 6 does not add public Prometheus/OpenMetrics endpoints, dashboards, alerting rules, decision caching, WAC/ACP/SAI policy evaluation, or production enforcement.

A later phase may expose metrics through an authenticated or deployment-local endpoint after naming, cardinality, access-control, and scraping behavior are specified.

## Verification

Run:

```sh
bash scripts/verify.sh all
```

Focused checks include:

- `internal/authz/metrics_test.go`
- `internal/authz/middleware_metrics_test.go`
- `internal/gateway/authz_shadow_test.go`

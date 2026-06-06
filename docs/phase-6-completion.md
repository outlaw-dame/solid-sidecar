# Phase 6 Completion: Privacy-Safe Shadow Observability

Phase 6 is complete when authz shadow behavior has privacy-safe aggregate observability without exposing users, resources, query strings, raw evaluator errors, policy contents, or request/audit hashes. Phase 6 remains non-enforcing. Community Solid Server remains the production Solid authorization authority.

## Completed scope

Phase 6 completed the following work:

1. Added `ShadowMetrics`, a thread-safe in-memory aggregate counter store for authz shadow events.
2. Added privacy-safe metric keys for event type, decision, reason code, and stable error reason labels.
3. Added snapshot support that returns a copy, not mutable internal state.
4. Added middleware metric recording for normal shadow decisions, warning paths, fallback decisions, and fallback failures.
5. Added gateway wiring so metrics are created only when authz shadow mode is enabled.
6. Added a gateway snapshot method for tests and future diagnostics without exposing request identifiers.
7. Added stable warning/metric labels for evaluator failures, invalid decisions, fallback failures, and backoff-active skips.
8. Added configurable, bounded external evaluator backoff fields while keeping local fallback and CSS pass-through behavior intact.
9. Added tests for snapshot copy semantics, concurrent metric recording, nil snapshots, middleware warning/decision behavior, gateway snapshot behavior, configurable backoff bounds, backoff-active warning classification, and aggregate-only metric dimensions.
10. Documented the observability contract in README and Phase 6 docs.

## Phase 6 guarantees

- Metrics are aggregate counters only.
- Metrics do not include WebIDs, client IDs, resource URIs, request IDs, query strings, raw evaluator errors, policy documents, request hashes, or policy hashes.
- Metric dimensions are restricted to event type, decision, reason code, and stable error reason labels.
- Backoff-active evaluator skips use the stable `backoff_active` reason label.
- Shadow mode remains non-enforcing.
- CSS remains authoritative for Solid authorization.
- Metrics are in-memory and process-local in the current phase.
- Snapshots copy internal counter state so callers cannot mutate live metrics.
- External evaluator failures, invalid outputs, backoff skips, and fallback failures remain observable but non-enforcing.

## Phase 6 non-goals

Phase 6 does not implement:

- Prometheus/OpenTelemetry export.
- Persistent metrics storage.
- per-user, per-resource, per-policy, or per-request drill-down.
- WAC, ACP, or SAI policy evaluation.
- RDF parsing or canonicalization.
- issuer/WebID authorization decisions.
- decision caching.
- production enforcement.

## Verification checklist

Run:

```sh
bash scripts/verify.sh all
```

Focused Go checks should cover:

- `internal/authz` metrics snapshot and concurrency tests.
- `internal/authz` aggregate metric-dimension contract tests.
- `internal/authz` middleware metric recording tests.
- `internal/authz` backoff-active warning classification tests.
- `internal/config` configurable backoff-bound validation tests.
- `internal/gateway` shadow-enabled and shadow-disabled metrics snapshot tests.
- existing non-enforcement and privacy-safe logging tests.

## Handoff to Phase 7

Phase 7 should start policy-input preparation without enforcement. Safe next work includes deterministic policy-source discovery, policy-document metadata contracts, and golden fixtures for WAC/ACP/SAI inputs. Enforcement must remain disabled until policy semantics and rollout gates are complete.

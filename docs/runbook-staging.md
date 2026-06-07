# Staging Runbook

This runbook describes how to introduce `solid-sidecar` in front of a staging Community Solid Server deployment.

The staging goal is pass-through safety and observability. CSS remains authoritative. Do not enable enforcement behavior in staging until the shadow path has proved stable and policy parsing/evaluation work is complete.

## Required readiness before staging

Before routing staging traffic through the sidecar:

- CI workflow is visible in GitHub Actions.
- CSS-through-sidecar e2e workflow is visible in GitHub Actions.
- `bash scripts/verify.sh go` passes locally or in CI.
- `bash scripts/verify.sh rust` passes locally or in CI.
- `bash scripts/verify.sh e2e` passes against the Docker-backed local harness.
- A rollback path to CSS-direct routing is documented for the staging environment.
- Sidecar logs are collected by the staging log pipeline.
- Operators know whether authz shadow mode is enabled or disabled.

## Recommended staging topology

Preferred first staging topology:

```text
client -> staging load balancer / ingress -> solid-sidecar -> CSS
```

Keep direct CSS access available internally for rollback and comparison, but do not expose both public paths as equivalent production endpoints.

## Initial staging configuration

Start with the safest settings:

```yaml
authz:
  shadow_enabled: false
  evaluator: local
```

Recommended first pass:

- sidecar proxying enabled;
- rate limiting enabled;
- security headers enabled;
- DPoP preflight enabled only if staging clients already send correct DPoP-shaped requests;
- authz shadow disabled until basic pass-through is proven.

After pass-through is stable, enable shadow mode:

```yaml
authz:
  shadow_enabled: true
  evaluator: local
```

External evaluator mode should stay disabled in staging until local shadow mode is stable.

## Deployment steps

1. Deploy the sidecar next to staging CSS.
2. Configure the sidecar backend URL to point at staging CSS.
3. Route a small internal-only test path through the sidecar.
4. Verify health:

   ```sh
   curl https://<staging-sidecar-host>/healthz
   curl https://<staging-sidecar-host>/readyz
   ```

5. Compare direct CSS and sidecar responses for safe methods:

   ```sh
   curl -i https://<staging-css-internal>/
   curl -i https://<staging-sidecar-host>/
   ```

6. Compare selected read-only resources through direct CSS and sidecar.
7. Confirm logs contain request IDs and no token or policy body leaks.
8. Move a small percentage of staging traffic through sidecar.
9. Monitor errors, latency, rate-limit events, readiness failures, and shadow warnings.
10. Increase staging coverage only after stability is observed.

## Staging smoke checks

Run these after every staging deployment:

```sh
curl -fsS https://<staging-sidecar-host>/healthz
curl -fsS https://<staging-sidecar-host>/readyz
curl -i https://<staging-sidecar-host>/
curl -I https://<staging-sidecar-host>/
```

Expected behavior:

- `/healthz` returns 200 when sidecar is alive.
- `/readyz` returns 200 only when CSS backend is reachable.
- GET and HEAD behavior should match CSS for comparable public resources.
- malformed or unsafe request paths should be rejected by the sidecar.

## Observability checklist

For every staging run, confirm visibility of:

- request count;
- status code distribution;
- sidecar rejection count;
- rate-limit count;
- backend readiness failures;
- authn preflight failures;
- authz shadow decisions if shadow mode is enabled;
- authz shadow warnings if evaluator errors occur;
- external evaluator backoff state if external evaluator mode is enabled.

Privacy requirements:

- do not log bearer tokens;
- do not log raw DPoP proofs;
- do not log policy document bodies;
- do not log request bodies;
- avoid query strings in warning logs;
- keep WebID/client identifiers out of aggregate metrics.

## Shadow-mode staging policy

Shadow mode is for observation only.

In staging, shadow decisions may be logged and counted, but they must not block CSS. A deny or invalid shadow decision must still pass through to CSS unless a future explicitly reviewed enforcement mode is enabled.

Before moving beyond local evaluator shadow mode:

- collect mismatch examples between CSS behavior and sidecar shadow output;
- confirm shadow warnings are stable and privacy-safe;
- confirm external evaluator fallback works if external evaluator mode is tested;
- confirm backoff prevents repeated failing evaluator calls.

## Rollback

Rollback must be possible without code changes.

Safe rollback options:

1. Route staging ingress directly back to CSS.
2. Disable the sidecar service in the staging deployment.
3. Disable authz shadow mode:

   ```yaml
   authz:
     shadow_enabled: false
   ```

4. Disable external evaluator mode:

   ```yaml
   authz:
     evaluator: local
   ```

Rollback verification:

```sh
curl -fsS https://<staging-css-or-ingress>/
curl -fsS https://<staging-css-or-ingress>/health-or-known-public-resource
```

## Stop conditions

Stop staging rollout and roll back if any of these occur:

- sidecar readiness flaps;
- sidecar changes CSS response status for normal pass-through requests;
- request latency increases beyond the staging budget;
- logs include tokens, request bodies, policy bodies, or unexpected query strings;
- shadow evaluator failures are noisy or repeated without backoff;
- rate limiting blocks expected staging clients;
- malformed request handling breaks legitimate clients;
- operators cannot distinguish sidecar failures from CSS failures.

## Promotion criteria from staging to parser work

Continue to authn and policy parsing implementation only after:

- CI checks are visible and reliable;
- Docker-backed e2e is stable;
- staging pass-through is stable;
- rollback has been tested;
- logs are privacy-safe;
- operators can identify sidecar health, CSS readiness, and shadow-mode state.

## What staging does not prove yet

Staging pass-through does not prove production authorization readiness.

Still required before enforcement:

- authoritative Solid-OIDC issuer and WebID validation;
- live policy source discovery;
- RDF parsing and canonicalization;
- WAC/ACP/SAI parsing;
- real policy evaluation;
- CSS behavior comparison;
- enforcement gates;
- emergency bypass;
- decision-cache safety.

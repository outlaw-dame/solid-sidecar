# CI and Verification

**Go Version Requirement: Go 1.25.x or later**

The project requires Go 1.25.x as the minimum baseline (declared in `go.mod`). This represents a major baseline change from earlier Go versions and was introduced to support newer language features and dependencies (particularly AWS SDK v2 and SSH/SFTP libraries).

**IMPORTANT:** Repository audit (`docs/repository-audit-2026-07-02.md` line 202) identifies this Go version change as significant and recommends explicit documentation in CI/runbooks.

The repository has two GitHub Actions workflows.

## CI

File: `.github/workflows/ci.yml`

Triggers:

- pull requests;
- pushes to `main`;
- manual `workflow_dispatch`.

Jobs:

- Go build and test;
- Rust policy kernel;
- vulnerability check.

The Go and Rust jobs call `scripts/verify.sh go` and `scripts/verify.sh rust`. The workflow has concurrency cancellation enabled for the same branch/ref and explicit job timeouts so stale or hung checks are easier to identify.

## CSS-through-sidecar e2e

File: `.github/workflows/e2e.yml`

Triggers:

- pull requests that touch sidecar/runtime/deploy/e2e paths;
- pushes to `main` that touch sidecar/runtime/deploy/e2e paths;
- manual `workflow_dispatch`.

The e2e workflow calls:

```sh
bash scripts/e2e-css.sh
```

It starts CSS and the sidecar with Docker Compose, waits for health/readiness, compares direct CSS and sidecar status codes for basic methods, checks sidecar path rejection behavior, and uploads the captured e2e log as an artifact.

## Local commands

Fast local verification:

```sh
bash scripts/verify.sh all
```

Docker-backed e2e verification:

```sh
bash scripts/verify.sh e2e
```

The e2e target is intentionally explicit because it requires Docker and starts CSS.

## Current policy

For now, PRs that touch runtime/deploy/e2e files should run both workflows. The e2e workflow should become a required branch protection check only after it proves stable on GitHub-hosted runners.

## Failure handling

If e2e fails:

1. Download the `css-through-sidecar-e2e-log` artifact.
2. Check the `docker compose ps` output.
3. Check CSS logs.
4. Check sidecar logs.
5. Re-run locally with:

```sh
SOLID_SIDECAR_E2E_WAIT_SECONDS=180 bash scripts/verify.sh e2e
```

Do not enable enforcement work until CI and e2e status are both visible and reliable.

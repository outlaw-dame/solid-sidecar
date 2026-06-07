# Local Runbook

This runbook explains how to run Community Solid Server behind `solid-sidecar` on a local machine.

## Requirements

- Go 1.22 or newer.
- Docker with Docker Compose v2.
- `curl`.
- Optional: Rust stable if running the Rust verification path.

## Run CSS behind the sidecar

From the repository root:

```sh
docker compose -f deploy/compose/docker-compose.dev.yml up --build
```

The Compose stack starts:

- CSS on `http://localhost:3000`;
- `solid-sidecar` on `http://localhost:8443`.

The sidecar forwards requests to CSS through the Docker network. Direct CSS access is exposed only for local debugging.

## Health checks

```sh
curl http://localhost:8443/healthz
curl http://localhost:8443/readyz
```

`/healthz` verifies the sidecar process is responding. `/readyz` verifies the configured CSS backend is reachable.

## Run the e2e harness

```sh
bash scripts/verify.sh e2e
```

This runs `scripts/e2e-css.sh`, which:

- starts an isolated Docker Compose project;
- waits for sidecar health and readiness;
- checks sidecar `/healthz` and `/readyz`;
- compares direct CSS and sidecar status codes for `GET /`, `HEAD /`, and `OPTIONS /`;
- checks that an encoded dot-segment path is rejected by the sidecar;
- prints CSS and sidecar logs if a check fails;
- removes the test containers and volume on exit.

The e2e target is intentionally not part of `scripts/verify.sh all` because it requires Docker and pulls/runs CSS.

## Run normal verification

```sh
bash scripts/verify.sh go
bash scripts/verify.sh rust
bash scripts/verify.sh all
```

`all` currently runs Go and Rust verification. It does not run Docker-backed e2e tests.

## Enable authz shadow mode locally

Edit `configs/sidecar.example.yaml` or override with environment variables:

```sh
SOLID_SIDECAR_AUTHZ_SHADOW_ENABLED=true \
SOLID_SIDECAR_AUTHZ_EVALUATOR=local \
go run ./cmd/solid-sidecar -config configs/sidecar.example.yaml
```

Shadow authz decisions are observable only. CSS remains authoritative.

## Enable external evaluator shadow mode locally

Use only a trusted local evaluator command:

```sh
SOLID_SIDECAR_AUTHZ_SHADOW_ENABLED=true \
SOLID_SIDECAR_AUTHZ_EVALUATOR=external_cli \
SOLID_SIDECAR_AUTHZ_EXTERNAL_COMMAND=/path/to/evaluator \
go run ./cmd/solid-sidecar -config configs/sidecar.example.yaml
```

The external evaluator path has timeout, output-size, fallback, and backoff controls. It is still shadow-only.

## Roll back to CSS-direct mode

Stop the sidecar stack and use CSS directly on port 3000:

```sh
docker compose -f deploy/compose/docker-compose.dev.yml down
```

Then run CSS directly using your preferred CSS command or the Compose `css` service only.

## Troubleshooting

If e2e fails, the script prints:

- `docker compose ps`;
- CSS logs;
- sidecar logs.

Common causes:

- Docker is not running.
- Ports `3000` or `8443` are already in use.
- CSS image pull failed.
- CSS startup took longer than `SOLID_SIDECAR_E2E_WAIT_SECONDS`.

You can increase the wait time:

```sh
SOLID_SIDECAR_E2E_WAIT_SECONDS=180 bash scripts/verify.sh e2e
```

# solid-sidecar

Go/Rust sidecar for Community Solid Server.

## Project Structure

This repository follows the recommended structure for a Solid Sidecar service:

- `cmd/`: Entry points for the Go sidecar service.
- `internal/`: Internal Go packages.
- `api/`: API definitions (OpenAPI, Protobuf).
- `rust/`: Rust-based kernels and services.
- `deploy/`: Deployment configurations (Docker, Compose, Helm).
- `configs/`: Configuration files for different environments.
- `tests/`: Contract, E2E, and security tests.
- `scripts/`: Development and utility scripts.
- `docs/`: Project documentation.

## Getting Started

Refer to the `docs/` directory for detailed information on architecture and integration.

#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify.sh [go|rust|all]

Runs the same verification commands used by CI.
USAGE
}

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "${script_dir}/.." && pwd
}

run_go() {
  local root
  root="$(repo_root)"
  cd "${root}"

  local unformatted
  unformatted="$(gofmt -l .)"
  if [[ -n "${unformatted}" ]]; then
    echo "Go files need gofmt:" >&2
    echo "${unformatted}" >&2
    return 1
  fi

  go vet ./...
  go test ./...
  go test -race ./...
  go build ./cmd/solid-sidecar
}

run_rust() {
  local root
  root="$(repo_root)"
  cd "${root}/rust"

  cargo fmt --all --check
  cargo test --workspace --all-targets
  cargo clippy --workspace --lib -- -D warnings
}

main() {
  local target
  target="${1:-all}"
  case "${target}" in
    go)
      run_go
      ;;
    rust)
      run_rust
      ;;
    all)
      run_go
      run_rust
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac
}

main "$@"

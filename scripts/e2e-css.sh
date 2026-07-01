#!/usr/bin/env bash
set -Eeuo pipefail

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "${script_dir}/.." && pwd
}

root="$(repo_root)"
compose_file="${root}/deploy/compose/docker-compose.dev.yml"
project_name="solid-sidecar-e2e"
sidecar_url="${SOLID_SIDECAR_E2E_URL:-http://127.0.0.1:8443}"
css_url="${SOLID_SIDECAR_E2E_CSS_URL:-http://127.0.0.1:3000}"
wait_seconds="${SOLID_SIDECAR_E2E_WAIT_SECONDS:-300}"

dump_logs() {
  echo "--- docker compose ps ---" >&2
  docker compose -p "${project_name}" -f "${compose_file}" ps >&2 || true
  echo "--- css logs ---" >&2
  docker compose -p "${project_name}" -f "${compose_file}" logs --no-color css > css.log 2>&1 || true
  docker compose -p "${project_name}" -f "${compose_file}" logs --no-color css >&2 || true
  echo "--- sidecar logs ---" >&2
  docker compose -p "${project_name}" -f "${compose_file}" logs --no-color sidecar > sidecar.log 2>&1 || true
  docker compose -p "${project_name}" -f "${compose_file}" logs --no-color sidecar >&2 || true
}

cleanup() {
  local status="$?"
  if [[ "${status}" != "0" ]]; then
    dump_logs
  fi
  docker compose -p "${project_name}" -f "${compose_file}" down -v --remove-orphans >/dev/null 2>&1 || true
  return "${status}"
}

status_code() {
  local method="$1"
  local url="$2"
  curl -sS -o /dev/null -w '%{http_code}' -X "${method}" "${url}"
}

assert_status() {
  local method="$1"
  local path="$2"
  local expected="$3"
  local actual
  echo "Checking ${method} ${path}..." >&2
  actual="$(status_code "${method}" "${sidecar_url}${path}")"
  echo "  Sidecar returned: ${actual} (expected: ${expected})" >&2
  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAILED: expected ${method} ${path} to return ${expected}, got ${actual}" >&2
    return 1
  fi
  echo "  PASSED" >&2
}

assert_sidecar_matches_css_status() {
  local method="$1"
  local path="$2"
  local direct proxied
  echo "Checking ${method} ${path} matches CSS..." >&2
  direct="$(status_code "${method}" "${css_url}${path}")"
  proxied="$(status_code "${method}" "${sidecar_url}${path}")"
  echo "  CSS status: ${direct}, Sidecar status: ${proxied}" >&2
  if [[ "${direct}" != "${proxied}" ]]; then
    echo "FAILED: expected ${method} ${path} sidecar status ${proxied} to match CSS status ${direct}" >&2
    return 1
  fi
  echo "  PASSED" >&2
}

wait_for() {
  local url="$1"
  local deadline=$((SECONDS + wait_seconds))
  echo "Waiting for ${url} (timeout: ${wait_seconds}s)..." >&2
  until curl -fsS "${url}" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "TIMED OUT: Failed to reach ${url} within ${wait_seconds}s" >&2
      echo "Trying to diagnose..." >&2
      echo "Current time: $(date)" >&2
      echo "Container status:" >&2
      docker compose -p "${project_name}" -f "${compose_file}" ps >&2
      return 1
    fi
    sleep 2
  done
  echo "Successfully connected to ${url}" >&2
}

main() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for CSS e2e tests" >&2
    return 2
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "docker compose is required for CSS e2e tests" >&2
    return 2
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required for CSS e2e tests" >&2
    return 2
  fi

  trap cleanup EXIT
  docker compose -p "${project_name}" -f "${compose_file}" down -v --remove-orphans >/dev/null 2>&1 || true

  echo "=== Starting containers with docker-compose ===" >&2
  docker compose -p "${project_name}" -f "${compose_file}" up --build -d
  echo "=== Containers started ===" >&2
  echo "" >&2
  echo "=== Container status ===" >&2
  docker compose -p "${project_name}" -f "${compose_file}" ps >&2
  echo "" >&2

  echo "=== Waiting for healthz endpoint ===" >&2
  wait_for "${sidecar_url}/healthz"
  echo "=== healthz is ready ===" >&2
  
  echo "=== Waiting for CSS to be accessible ===" >&2
  wait_for "${css_url}/"
  echo "=== CSS is ready ===" >&2
  
  echo "=== Waiting for readyz endpoint ===" >&2
  wait_for "${sidecar_url}/readyz"

  assert_status GET /healthz 200
  assert_status GET /readyz 200

  assert_sidecar_matches_css_status GET /
  assert_sidecar_matches_css_status HEAD /
  assert_sidecar_matches_css_status OPTIONS /

  malformed_status="$(status_code GET '/%2e%2e/')"
  if [[ "${malformed_status}" != "400" && "${malformed_status}" != "403" ]]; then
    echo "expected encoded dot-segment path to be rejected, got ${malformed_status}" >&2
    return 1
  fi

  echo "CSS-through-sidecar e2e checks passed"
}

main "$@"

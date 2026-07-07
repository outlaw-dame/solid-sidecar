#!/bin/bash
#
# Solid Sidecar HTTP Client Example: List Container
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Resource Operations
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# Status: STABLE - Production Ready
#
# Description:
#   This script lists the contents of a container on Solid Sidecar.
#
# Usage:
#   ./list-container.sh [options] CONTAINER_URI
#
# Options:
#   --sidecar-url URL      Solid Sidecar base URL (default: $SOLID_SIDECAR_URL)
#   --access-token TOKEN    Access token (required, or from $ACCESS_TOKEN)
#   --dpop-proof PROOF      DPoP proof JWT (required, or from $DPOP_PROOF)
#   --accept CONTENT_TYPE   Accept header (default: text/turtle)
#   --quiet                Suppress progress messages
#   --help                 Show this help
#
# Arguments:
#   CONTAINER_URI          Container URI (required)
#
# Dependencies: curl
#

set -euo pipefail

SOLID_SIDECAR_URL_DEFAULT="http://localhost:8080"
TIMEOUT=30
MAX_RETRIES=3
RETRY_DELAY=1

ERROR_INVALID=1
ERROR_NETWORK=2
ERROR_AUTH=3
ERROR_NOT_FOUND=4

log_info() { [ "${QUIET:-}" = "true" ] && return; echo "[INFO] $*" >&2; }
log_warn() { [ "${QUIET:-}" = "true" ] && return; echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

validate() { [ -z "$1" ] && { log_error "$2 is required"; return $ERROR_INVALID; } || return 0; }

resolve_url() {
    local base="$1" uri="$2"
    [[ "$uri" =~ ^https?:// ]] && echo "$uri" && return
    base=${base%/}
    [[ "$uri" =~ ^/ ]] && echo "${base}${uri}" || echo "${base}/${uri}"
}

main() {
    local sidecar="${SOLID_SIDECAR_URL:-$SOLID_SIDECAR_URL_DEFAULT}"
    local token="${ACCESS_TOKEN:-}" proof="${DPOP_PROOF:-}"
    local accept="${ACCEPT:-text/turtle}" quiet=false help=false
    local uri=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --sidecar-url) sidecar="$2"; shift 2;;
            --access-token) token="$2"; shift 2;;
            --dpop-proof) proof="$2"; shift 2;;
            --accept) accept="$2"; shift 2;;
            --quiet) quiet=true; shift;;
            --help) help=true; shift;;
            *) [[ "$1" =~ ^-- ]] && { log_error "Unknown: $1"; help=true; return $ERROR_INVALID; }
               uri="$1"; shift;;
        esac
    done

    $help && { grep '^# ' "$0" | sed 's/^# //'; return 0; }
    QUIET="$quiet"

    validate "$uri" "container URI" || return $?
    validate "$token" "access_token" || return $?
    validate "$proof" "DPoP proof" || return $?

    local url=$(resolve_url "$sidecar" "$uri")
    log_info "GET ${url} (container listing)"

    local retry=0
    while [ $retry -lt $MAX_RETRIES ]; do
        retry=$((retry+1))
        local args=(-i -s -S --max-time $TIMEOUT --retry 0 -X GET
            -H "Authorization: DPoP ${token}" -H "DPoP: ${proof}" -H "Accept: ${accept}")
        args+=("$url")

        local resp; resp=$(curl "${args[@]}" 2>&1) || true
        [ $? -ne 0 ] && {
            [[ "$resp" =~ (Connection|refused|timed|Temporary) ]] && { log_warn "Retry $retry"; sleep $RETRY_DELAY; continue; }
            log_error "Curl: $resp"; return $ERROR_NETWORK;
        }

        local code=$(head -n1 <<< "$resp" | awk '{print $2}')
        case "$code" in
            200) break ;;
            401) log_error "Unauthorized"; return $ERROR_AUTH ;;
            403) log_error "Forbidden"; return $ERROR_AUTH ;;
            404) log_error "Not found: ${uri}"; return $ERROR_NOT_FOUND ;;
            429) local ra=$(grep -i 'retry-after' <<< "$resp" | head -1 | awk '{print $2}' || echo $RETRY_DELAY)
                 log_warn "Rate limited, retry after ${ra}s"; sleep $ra; continue ;;
            5*) log_warn "Server error $code, retry $retry"; sleep $RETRY_DELAY; continue ;;
            *) log_error "HTTP $code"; return $ERROR_NETWORK ;;
        esac
    done

    [ $retry -ge $MAX_RETRIES ] && { log_error "Failed after $MAX_RETRIES retries"; return $ERROR_NETWORK; }
    echo "$resp"
}
main "$@"

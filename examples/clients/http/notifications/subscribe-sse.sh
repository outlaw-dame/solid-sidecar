#!/bin/bash
#
# Solid Sidecar HTTP Client Example: Subscribe to Notifications (SSE)
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Notifications
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# Status: STABLE - Production Ready
#
# Description:
#   This script subscribes to Server-Sent Events (SSE) notifications from Solid Sidecar.
#   It connects to the notifications endpoint and listens for events.
#
# Security Level: CRITICAL - This script handles credentials and real-time data
#
# Usage:
#   ./subscribe-sse.sh [options] [RESOURCE_URI]
#
# Options:
#   --sidecar-url URL      Solid Sidecar base URL (default: $SOLID_SIDECAR_URL)
#   --access-token TOKEN    Access token (required, or from $ACCESS_TOKEN)
#   --dpop-proof PROOF      DPoP proof JWT (required, or from $DPOP_PROOF)
#   --cursor ID             Last event ID to resume from (optional)
#   --timeout SECONDS      Connection timeout (default: 0 = infinite)
#   --max-events N         Maximum events to receive (default: 0 = infinite)
#   --quiet                Suppress progress messages
#   --help                 Show this help
#
# Arguments:
#   RESOURCE_URI          Resource or container URI to subscribe to (default: root)
#
# Dependencies: curl
#
# Security Notes:
#   - NEVER hardcode access tokens or DPoP proofs in scripts
#   - Always use environment variables or secure input for credentials
#   - Validate all URLs before sending requests
#   - Never log full tokens or DPoP proofs
#   - Use HTTPS for all production endpoints
#

set -euo pipefail

SOLID_SIDECAR_URL_DEFAULT="http://localhost:8080"
NOTIFICATIONS_ENDPOINT="/notifications"
MAX_RETRIES=5
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

# Parse SSE events from stream
parse_sse() {
    local event_id="" event_type="" event_data=""
    
    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue
        
        # Check for event type
        if [[ "$line" == Event:* ]]; then
            event_type="${line#Event: }"
            continue
        fi
        
        # Check for event ID
        if [[ "$line" == id:* ]]; then
            event_id="${line#id: }"
            continue
        fi
        
        # Check for data
        if [[ "$line" == data:* ]]; then
            local data_line="${line#data: }"
            # Handle multi-line data
            while [[ "$data_line" == *$'\n' ]] || [[ "$data_line" == *$'\r' ]]; do
                event_data+="${data_line%%[$'\n\r']*}"
                read -r line || break
                if [[ "$line" == data:* ]]; then
                    data_line="${line#data: }"
                    event_data+="\n"
                else
                    break
                fi
            done
            event_data+="${data_line}"
            continue
        fi
        
        # Skip comments
        [[ "$line" == \#* ]] && continue
        
        # If we have data, output the event
        if [ -n "$event_data" ]; then
            local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            echo "[${timestamp}] Event: ${event_type:-unknown} (id: ${event_id:-none})"
            echo "${event_data}"
            echo "---"
            
            # Reset for next event
            event_id=""
            event_type=""
            event_data=""
            
            # Increment event count
            EVENT_COUNT=$((EVENT_COUNT + 1))
            
            # Check max events
            [ "$MAX_EVENTS" -gt 0 ] && [ $EVENT_COUNT -ge $MAX_EVENTS ] && return 0
        fi
    done
}

main() {
    local sidecar="${SOLID_SIDECAR_URL:-$SOLID_SIDECAR_URL_DEFAULT}"
    local token="${ACCESS_TOKEN:-}" proof="${DPOP_PROOF:-}"
    local cursor="${CURSOR:-}" timeout="${SSE_TIMEOUT:-0}"
    local max_events="${MAX_EVENTS:-0}" quiet=false help=false
    local resource_uri=""

    # Parse options
    while [ $# -gt 0 ]; do
        case "$1" in
            --sidecar-url) sidecar="$2"; shift 2;;
            --access-token) token="$2"; shift 2;;
            --dpop-proof) proof="$2"; shift 2;;
            --cursor) cursor="$2"; shift 2;;
            --timeout) timeout="$2"; shift 2;;
            --max-events) max_events="$2"; shift 2;;
            --quiet) quiet=true; shift;;
            --help) help=true; shift;;
            *) [[ "$1" =~ ^-- ]] && { log_error "Unknown: $1"; help=true; return $ERROR_INVALID; }
               resource_uri="$1"; shift;;
        esac
    done

    $help && { grep '^# ' "$0" | sed 's/^# //'; return 0; }
    QUIET="$quiet"

    validate "$token" "access_token" || return $?
    validate "$proof" "DPoP proof" || return $?

    # Default resource URI is root
    [ -z "$resource_uri" ] && resource_uri="/"

    # Build notifications URL
    local notifications_url="${sidecar}${NOTIFICATIONS_ENDPOINT}"
    
    # Add resource query parameter
    local resource_param
    resource_param=$(resolve_url "$sidecar" "$resource_uri" | sed 's|/|%2F|g')
    
    local url="${notifications_url}?resource=${resource_param}"
    
    # Add cursor if specified
    [ -n "$cursor" ] && url+="&cursor=${cursor}"
    
    log_info "Subscribing to notifications for: ${resource_uri}"
    log_info "SSE endpoint: ${url}"
    
    # Set up curl for SSE
    local curl_args=(
        -s -S --no-buffer
        --max-time "$timeout"
        --retry 0
        -H "Authorization: DPoP ${token}"
        -H "DPoP: ${proof}"
        -H "Accept: text/event-stream"
    )
    
    [ -n "$cursor" ] && curl_args+=(-H "Last-Event-ID: ${cursor}")
    
    curl_args+=("$url")
    
    # Initialize event counter
    EVENT_COUNT=0
    MAX_EVENTS=$max_events
    
    log_info "Starting SSE connection (press Ctrl+C to stop)..."
    
    # Use curl to connect and parse events
    curl "${curl_args[@]}" 2>/dev/null | parse_sse
    
    log_info "SSE connection closed"
    log_info "Total events received: $EVENT_COUNT"
}
main "$@"

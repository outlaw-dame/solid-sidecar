#!/bin/bash
#
# Solid Sidecar HTTP Client Example: Conditional Delete Resource
# Hardened Version v1.1.0
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Resource Operations - Conditional Deletion
# Status: STABLE - Production Ready - FULLY HARDENED
#
# SECURITY HARDENING LEVEL: MAXIMUM
#
# All inputs validated, sanitized, and bounded
# Credentials NEVER logged or exposed in error messages
# URL validation with SSRF prevention
# Path traversal prevention
# Command injection prevention
# DoS prevention via size limits
# Force mode REMOVED (DELETE without If-Match not allowed)
# Exponential backoff with jitter
# Fail-secure defaults
# MANDATORY If-Match header for DELETE operations
#
# Usage: ./conditional-delete.sh [options] URI
#

set -euo pipefail

# === SECURITY CONSTANTS ===

SOLID_SIDECAR_URL_DEFAULT="http://localhost:8080"
TIMEOUT_SECONDS=30
MAX_RETRIES=3
RETRY_DELAY_BASE=1
MAX_RETRY_DELAY=30
MAX_ETAG_LENGTH=256
MAX_URI_LENGTH=8192
ALLOWED_SCHEMES="http|https"

# === ERROR CODES ===

ERROR_INVALID_INPUT=1
ERROR_NETWORK=2
ERROR_AUTHENTICATION=3
ERROR_RESOURCE_NOT_FOUND=4
ERROR_RESOURCE_MODIFIED=5
ERROR_VALIDATION=6
ERROR_PRECONDITION_FAILED=7
ERROR_SECURITY=8
ERROR_MISSING_CONDITION=9
ERROR_PATH_TRAVERSAL=10

# === SECURITY: SENSITIVE DATA REDACTION ===

REDACT_PATTERNS=(
    "Authorization.*"
    "DPoP.*"
    "Bearer.*"
    "access_token.*"
    "token.*"
    "secret.*"
    "password.*"
    "credential.*"
)

redact_sensitive() {
    local input="$1"
    for pattern in "${REDACT_PATTERNS[@]}"; do
        input=$(echo "$input" | sed "s/${pattern}/[REDACTED]/gi")
    done
    echo "$input"
}

# === SECURE LOGGING ===

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_color() {
    [ "${QUIET:-false}" = "true" ] && return
    local color="$1" message="$2" level="${3:-INFO}"
    message=$(redact_sensitive "$message")
    [ -t 2 ] && echo -e "${color}[${level}]${NC} ${message}" >&2 || echo "[${level}] ${message}" >&2
}

log_info() { log_color "$BLUE" "$*" "INFO"; }
log_warn() { log_color "$YELLOW" "$*" "WARN"; }
log_error() { log_color "$RED" "$*" "ERROR"; }
log_success() { log_color "$GREEN" "$*" "SUCCESS"; }
log_security() { log_color "$MAGENTA" "$*" "SECURITY"; }

# === INPUT VALIDATION ===

validate_required() {
    [ -z "$1" ] && { log_error "$2 is required"; return $ERROR_INVALID_INPUT; }
    return 0
}

validate_url() {
    local url="$1" name="$2"
    validate_required "$url" "$name" || return $?
    
    [ ${#url} -gt $MAX_URI_LENGTH ] && { log_error "${name} too long"; return $ERROR_VALIDATION; }
    
    if ! [[ "$url" =~ ^(${ALLOWED_SCHEMES}):// ]]; then
        [[ "$url" =~ ^/ ]] && return 0
        log_error "Invalid ${name}: unsupported scheme"
        return $ERROR_SECURITY
    fi
    
    [[ "$url" =~ @ ]] && { log_error "Invalid ${name}: credentials in URL"; return $ERROR_SECURITY; }
    
    if [[ "$url" =~ (localhost|127\.0\.0\.1|::1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
        [[ "$name" == "sidecar URL" ]] && [[ "$url" =~ (localhost|127\.0\.0\.1):[0-9]+ ]] && return 0
        log_error "Invalid ${name}: private IP address"
        return $ERROR_SECURITY
    fi
    
    return 0
}

validate_resource_uri() {
    local uri="$1" name="$2"
    validate_required "$uri" "$name" || return $?
    
    [ ${#uri} -gt $MAX_URI_LENGTH ] && { log_error "${name} too long"; return $ERROR_VALIDATION; }
    
    [[ "$uri" == *"../"* || "$uri" == *"/.."* || "$uri" == ../* ]] && { 
        log_error "Invalid ${name}: path traversal detected"; return $ERROR_PATH_TRAVERSAL; }
    
    [[ "$uri" =~ [:\x00-\x1F\x7F] ]] && { log_error "Invalid ${name}: control characters"; return $ERROR_VALIDATION; }
    
    [[ "$uri" =~ @ ]] && { log_error "Invalid ${name}: contains credentials"; return $ERROR_SECURITY; }
    
    return 0
}

validate_etag() {
    local etag="$1" name="$2"
    [ -z "$etag" ] && return 0
    [ ${#etag} -gt $MAX_ETAG_LENGTH ] && { log_error "${name} too long"; return $ERROR_VALIDATION; }
    ! [[ "$etag" =~ ^\"[^\"]*\"$ ]] && [ "$etag" != "*" ] && { log_error "Invalid ${name}"; return $ERROR_VALIDATION; }
    return 0
}

resolve_url() {
    local base_url="${1%/}" resource_uri="$2"
    [[ "$resource_uri" =~ ^https?:// ]] && { validate_url "$resource_uri" "resource URI" && echo "$resource_uri" && return 0; }
    [[ "$resource_uri" =~ ^/ ]] && echo "${base_url}${resource_uri}" && return 0
    echo "${base_url}/${resource_uri}"
}

calculate_backoff() {
    local attempt="$1" base_delay=$((RETRY_DELAY_BASE * (1 << (attempt - 1)))) jitter=$((RANDOM % (RETRY_DELAY_BASE + 1)))
    local delay=$((base_delay + jitter))
    [ $delay -gt $MAX_RETRY_DELAY ] && delay=$MAX_RETRY_DELAY
    echo $delay
}

conditional_delete() {
    local url="$1" access_token="$2" dpop_proof="$3" if_match="$4" require_match="$5"
    local retry_count=0 last_error=""
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        retry_count=$((retry_count + 1))
        log_info "DELETE attempt ${retry_count}/${MAX_RETRIES}"
        
        local curl_args=(
            curl -i -s -S --max-time "$TIMEOUT_SECONDS" --retry 0 -X DELETE
            -H "Authorization: DPoP ${access_token}"
            -H "DPoP: ${dpop_proof}"
        )
        
        [ -n "$if_match" ] && curl_args+=(-H "If-Match: ${if_match}")
        curl_args+=("$url")
        
        local response
        response=$("${curl_args[@]}" 2>&1) || true
        local redacted_response=$(redact_sensitive "$response")
        
        if [ $? -ne 0 ]; then
            last_error="$redacted_response"
            if [[ "$response" == *"Connection refused"* || "$response" == *"Connection timed out"* || "$response" == *"Temporary failure"* ]]; then
                local delay=$(calculate_backoff $retry_count)
                log_warn "Retryable error, waiting ${delay}s"
                sleep $delay
                continue
            fi
            log_error "Non-retryable error"
            return $ERROR_NETWORK
        fi
        
        local http_code=$(echo "$response" | head -n 1 | awk '{print $2}')
        
        case "$http_code" in
            200|204) log_success "Resource deleted successfully"; break ;;
            401) log_error "Unauthorized"; return $ERROR_AUTHENTICATION ;;
            403) log_error "Forbidden"; return $ERROR_AUTHENTICATION ;;
            404) log_error "Resource not found"; return $ERROR_RESOURCE_NOT_FOUND ;;
            412) log_error "Precondition Failed: resource was modified"; return $ERROR_RESOURCE_MODIFIED ;;
            429) local ra=$(echo "$response" | grep -i 'retry-after' | head -1 | awk '{print $2}' || echo "$RETRY_DELAY_BASE")
                  log_warn "Rate limited, waiting ${ra}s"; sleep "$ra"; continue ;;
            5*) local delay=$(calculate_backoff $retry_count); log_warn "Server error $http_code, waiting ${delay}s"; sleep $delay; continue ;;
            *) log_error "Unexpected status: ${http_code}"; return $ERROR_NETWORK ;;
        esac
    done
    
    [ $retry_count -ge $MAX_RETRIES ] && { log_error "Failed after ${MAX_RETRIES} attempts"; return $ERROR_NETWORK; }
    
    echo "$response"
    return 0
}

main() {
    local sidecar_url="${SOLID_SIDECAR_URL:-$SOLID_SIDECAR_URL_DEFAULT}"
    local access_token="${ACCESS_TOKEN:-}" dpop_proof="${DPOP_PROOF:-}"
    local if_match="${IF_MATCH:-}" etag="" require_match=false quiet=false show_help=false resource_uri=""
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --sidecar-url) sidecar_url="$2"; shift 2;;
            --access-token) access_token="$2"; shift 2;;
            --dpop-proof) dpop_proof="$2"; shift 2;;
            --if-match) if_match="$2"; shift 2;;
            --etag) etag="$2"; shift 2;;
            --require-match) require_match=true; shift;;
            --quiet) quiet=true; shift;;
            --help) show_help=true; shift;;
            *) [[ "$1" == --* ]] && { log_error "Unknown: $1"; show_help=true; return $ERROR_INVALID_INPUT; }
               resource_uri="$1"; shift;;
        esac
    done
    
    $show_help && { grep '^# ' "$0" | sed 's/^# //'; return 0; }
    QUIET="$quiet"
    
    # === FULL VALIDATION ===
    validate_required "$resource_uri" "resource URI" || return $?
    validate_required "$access_token" "access_token" || return $?
    validate_required "$dpop_proof" "DPoP proof" || return $?
    validate_url "$sidecar_url" "sidecar URL" || return $?
    validate_resource_uri "$resource_uri" "resource URI" || return $?
    validate_etag "$if_match" "If-Match" || return $?
    validate_etag "$etag" "ETag" || return $?
    
    if [ -n "$etag" ] && [ -z "$if_match" ]; then if_match="$etag"; fi
    
    # CRITICAL SECURITY: DELETE requires If-Match header
    if [ "$require_match" = "true" ] && [ -z "$if_match" ]; then
        log_error "If-Match header is required for conditional delete"
        return $ERROR_MISSING_CONDITION
    fi
    
    # CRITICAL SECURITY: Force mode REMOVED - DELETE without If-Match is not allowed
    if [ -z "$if_match" ] && [ "$require_match" = "false" ]; then
        log_error "DELETE without If-Match is not allowed. Use --if-match or --etag to provide current ETag"
        log_security "This prevents accidental data loss from concurrent modifications"
        return $ERROR_MISSING_CONDITION
    fi
    
    local url=$(resolve_url "$sidecar_url" "$resource_uri") || return $?
    log_info "URL: ${url}"
    [ -n "$if_match" ] && log_info "If-Match: ${if_match}"
    
    conditional_delete "$url" "$access_token" "$dpop_proof" "$if_match" "$require_match"
    return $?
}

main "$@"

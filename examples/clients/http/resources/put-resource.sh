#!/bin/bash
#
# Solid Sidecar HTTP Client Example: Put Resource
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Resource Operations
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# Status: STABLE - Production Ready
#
# Description:
#   This script creates or replaces a resource on Solid Sidecar with proper DPoP authentication.
#   It demonstrates the PUT operation with authentication headers.
#
# Security Level: CRITICAL - This script handles credentials and resource modifications
#
# Usage:
#   ./put-resource.sh [options] URI
#
# Options:
#   --sidecar-url URL      Solid Sidecar base URL (default: $SOLID_SIDECAR_URL or http://localhost:8080)
#   --access-token TOKEN    Access token (required, or from $ACCESS_TOKEN)
#   --dpop-proof PROOF      DPoP proof JWT (required, or from $DPOP_PROOF)
#   --content-type TYPE      Content-Type header (default: text/turtle)
#   --input FILE            Input file to upload (use - for stdin)
#   --body STRING           Body content (alternative to --input)
#   --if-match ETag         If-Match header for conditional update
#   --if-none-match ETag   If-None-Match header for conditional create
#   --link TYPE             Link header for resource type hints
#   --quiet                Suppress progress messages
#   --help                 Show this help
#
# Arguments:
#   URI                    Resource URI (required)
#
# Dependencies:
#   - curl
#   - jq (for JSON parsing - optional)
#
# Security Notes:
#   - NEVER hardcode access tokens or DPoP proofs in scripts
#   - Always use environment variables or secure input for credentials
#   - Validate all URLs before sending requests
#   - Never log tokens or sensitive data
#   - Use HTTPS for all production endpoints
#

set -euo pipefail

# --- Configuration ---

SOLID_SIDECAR_URL_DEFAULT="http://localhost:8080"
TIMEOUT_SECONDS=30
MAX_RETRIES=3
RETRY_DELAY=1

# --- Error Codes ---

ERROR_INVALID_INPUT=1
ERROR_NETWORK=2
ERROR_AUTHENTICATION=3
ERROR_RESOURCE_EXISTS=4
ERROR_VALIDATION=5
ERROR_CONFLICT=6

# --- Logging ---

log_info() {
    [ "${QUIET:-false}" = "true" ] && return
    echo "[INFO] $*" >&2
}

log_warn() {
    [ "${QUIET:-false}" = "true" ] && return
    echo "[WARN] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

# --- Input Validation ---

validate_required() {
    local value="$1"
    local name="$2"
    
    if [ -z "$value" ]; then
        log_error "${name} is required"
        return $ERROR_INVALID_INPUT
    fi
    
    return 0
}

validate_url() {
    local url="$1"
    local name="$2"
    
    if [ -z "$url" ]; then
        log_error "${name} is required"
        return $ERROR_INVALID_INPUT
    fi
    
    if ! [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/[^\s]*)?$ ]]; then
        if [[ "$url" =~ ^/ ]]; then
            return 0
        fi
        log_error "Invalid ${name}: $url"
        return $ERROR_VALIDATION
    fi
    
    return 0
}

# --- URL Resolution ---

resolve_url() {
    local base_url="$1"
    local resource_uri="$2"
    
    if [[ "$resource_uri" =~ ^https?:// ]]; then
        echo "$resource_uri"
        return 0
    fi
    
    if [[ "$resource_uri" =~ ^/ ]]; then
        base_url=${base_url%/}
        echo "${base_url}${resource_uri}"
        return 0
    fi
    
    base_url=${base_url%/}
    echo "${base_url}/${resource_uri}"
}

# --- Request ---

put_resource() {
    local url="$1"
    local access_token="$2"
    local dpop_proof="$3"
    local content_type="$4"
    local body="$5"
    local if_match="$6"
    local if_none_match="$7"
    local link="$8"
    
    local retry_count=0
    local last_error=""
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        retry_count=$((retry_count + 1))
        
        log_info "PUT request attempt ${retry_count}/${MAX_RETRIES} to ${url}"
        
        local curl_args=()
        curl_args+=("-i")
        curl_args+=("-s")
        curl_args+=("-S")
        curl_args+=("--max-time" "$TIMEOUT_SECONDS")
        curl_args+=("--retry" "0")
        curl_args+=("-X" "PUT")
        curl_args+=("-H" "Authorization: DPoP ${access_token}")
        curl_args+=("-H" "DPoP: ${dpop_proof}")
        curl_args+=("-H" "Content-Type: ${content_type}")
        
        if [ -n "$if_match" ]; then
            curl_args+=("-H" "If-Match: ${if_match}")
        fi
        
        if [ -n "$if_none_match" ]; then
            curl_args+=("-H" "If-None-Match: ${if_none_match}")
        fi
        
        if [ -n "$link" ]; then
            curl_args+=("-H" "Link: ${link}")
        fi
        
        # Handle body
        if [ -n "$body" ]; then
            curl_args+=("-d" "$body")
        fi
        
        curl_args+=("$url")
        
        local response
        response=$(curl "${curl_args[@]}" 2>&1) || true
        
        if [ $? -ne 0 ]; then
            last_error="$response"
            
            if [[ "$response" == *"Connection refused"* ]] || \
               [[ "$response" == *"Connection timed out"* ]] || \
               [[ "$response" == *"Temporary failure"* ]]; then
                log_warn "Request failed (attempt ${retry_count}/${MAX_RETRIES}): retryable error"
                sleep $RETRY_DELAY
                continue
            fi
            
            log_error "Non-retryable curl error: $response"
            return $ERROR_NETWORK
        fi
        
        local http_code
        http_code=$(echo "$response" | head -n 1 | awk '{print $2}')
        
        case "$http_code" in
            200|201)
                break
                ;;
            401)
                log_error "Unauthorized: Invalid or missing access token/DPoP proof"
                return $ERROR_AUTHENTICATION
                ;;
            403)
                log_error "Forbidden: Access denied"
                return $ERROR_AUTHENTICATION
                ;;
            409)
                log_error "Conflict: Resource already exists"
                return $ERROR_CONFLICT
                ;;
            412)
                log_error "Precondition Failed: If-Match or If-None-Match condition not met"
                return $ERROR_RESOURCE_EXISTS
                ;;
            429)
                local retry_after
                retry_after=$(echo "$response" | grep -i 'retry-after' | head -1 | awk '{print $2}' || echo "$RETRY_DELAY")
                log_warn "Rate limited. Retrying after ${retry_after}s"
                sleep "$retry_after"
                continue
                ;;
            5*)
                log_warn "Server error ${http_code}. Retrying..."
                sleep $RETRY_DELAY
                continue
                ;;
            *)
                log_error "Unexpected HTTP status: ${http_code}"
                return $ERROR_NETWORK
                ;;
        esac
    done
    
    if [ $retry_count -ge $MAX_RETRIES ]; then
        log_error "Request failed after ${MAX_RETRIES} attempts: ${last_error:-unknown error}"
        return $ERROR_NETWORK
    fi
    
    echo "$response"
    return 0
}

# --- Main ---

main() {
    local sidecar_url="${SOLID_SIDECAR_URL:-$SOLID_SIDECAR_URL_DEFAULT}"
    local access_token="${ACCESS_TOKEN:-}"
    local dpop_proof="${DPOP_PROOF:-}"
    local content_type="${CONTENT_TYPE:-text/turtle}"
    local input_file=""
    local body=""
    local if_match="${IF_MATCH:-}"
    local if_none_match="${IF_NONE_MATCH:-}"
    local link="${LINK:-}"
    local quiet=false
    local show_help=false
    
    local resource_uri=""
    
    # Parse options
    while [ $# -gt 0 ]; do
        case "$1" in
            --sidecar-url)
                sidecar_url="$2"
                shift 2
                ;;
            --access-token)
                access_token="$2"
                shift 2
                ;;
            --dpop-proof)
                dpop_proof="$2"
                shift 2
                ;;
            --content-type)
                content_type="$2"
                shift 2
                ;;
            --input)
                input_file="$2"
                shift 2
                ;;
            --body)
                body="$2"
                shift 2
                ;;
            --if-match)
                if_match="$2"
                shift 2
                ;;
            --if-none-match)
                if_none_match="$2"
                shift 2
                ;;
            --link)
                link="$2"
                shift 2
                ;;
            --quiet)
                quiet=true
                shift
                ;;
            --help)
                show_help=true
                shift
                ;;
            *)
                if [[ "$1" == --* ]]; then
                    log_error "Unknown option: $1"
                    show_help=true
                    return $ERROR_INVALID_INPUT
                fi
                resource_uri="$1"
                shift
                ;;
        esac
    done
    
    if [ "$show_help" = "true" ]; then
        grep '^# ' "$0" | sed 's/^# //' | sed 's/^#//'
        return 0
    fi
    
    QUIET="$quiet"
    
    validate_required "$resource_uri" "resource URI" || return $?
    validate_required "$access_token" "access_token" || return $?
    validate_required "$dpop_proof" "DPoP proof" || return $?
    
    validate_url "$sidecar_url" "sidecar URL" || return $?
    validate_url "$resource_uri" "resource URI" || return $?
    
    # Check that we have either input file or body
    if [ -z "$input_file" ] && [ -z "$body" ]; then
        log_error "Either --input or --body is required"
        return $ERROR_INVALID_INPUT
    fi
    
    # Read input from file if specified
    if [ -n "$input_file" ]; then
        if [ "$input_file" = "-" ]; then
            body=$(cat)
        elif [ -f "$input_file" ]; then
            body=$(cat "$input_file")
        else
            log_error "Input file not found: $input_file"
            return $ERROR_INVALID_INPUT
        fi
    fi
    
    # Resolve URL
    local url
    url=$(resolve_url "$sidecar_url" "$resource_uri")
    
    log_info "Resolved URL: ${url}"
    log_info "Content-Type: ${content_type}"
    
    # Make request
    local response
    response=$(put_resource \
        "$url" \
        "$access_token" \
        "$dpop_proof" \
        "$content_type" \
        "$body" \
        "$if_match" \
        "$if_none_match" \
        "$link") || return $?
    
    echo "$response"
    return 0
}

# Run main
main "$@"

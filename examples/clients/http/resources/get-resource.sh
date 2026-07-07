#!/bin/bash
#
# Solid Sidecar HTTP Client Example: Get Resource
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Resource Operations
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# Status: STABLE - Production Ready
#
# Description:
#   This script retrieves a resource from Solid Sidecar with proper DPoP authentication.
#   It demonstrates the GET operation with authentication headers.
#
# Security Level: CRITICAL - This script handles credentials and resource access
#
# Usage:
#   ./get-resource.sh [options] URI
#
# Options:
#   --sidecar-url URL      Solid Sidecar base URL (default: $SOLID_SIDECAR_URL or http://localhost:8080)
#   --access-token TOKEN    Access token (required, or from $ACCESS_TOKEN)
#   --dpop-proof PROOF      DPoP proof JWT (required, or from $DPOP_PROOF)
#   --accept CONTENT_TYPE   Accept header (default: */*)
#   --output FILE           Output resource to FILE (default: stdout)
#   --headers-only          Only retrieve headers (HEAD request)
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
ERROR_RESOURCE_NOT_FOUND=4
ERROR_VALIDATION=5

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
    
    # Check if valid URL
    if ! [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/[^\s]*)?$ ]]; then
        # If it doesn't have a scheme, try to prepend the sidecar URL
        if [[ "$url" =~ ^/ ]]; then
            # It's a path, we'll handle it later
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
    
    # If resource_uri already has a scheme, use it as-is
    if [[ "$resource_uri" =~ ^https?:// ]]; then
        echo "$resource_uri"
        return 0
    fi
    
    # If resource_uri starts with /, it's a path
    if [[ "$resource_uri" =~ ^/ ]]; then
        # Remove trailing slash from base_url
        base_url=${base_url%/}
        echo "${base_url}${resource_uri}"
        return 0
    fi
    
    # Otherwise, treat as relative path
    base_url=${base_url%/}
    echo "${base_url}/${resource_uri}"
}

# --- Request ---

get_resource() {
    local url="$1"
    local access_token="$2"
    local dpop_proof="$3"
    local accept="$4"
    local headers_only=false
    
    if [ "$5" = "true" ]; then
        headers_only=true
    fi
    
    local retry_count=0
    local last_error=""
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        retry_count=$((retry_count + 1))
        
        log_info "GET request attempt ${retry_count}/${MAX_RETRIES} to ${url}"
        
        local curl_args=()
        curl_args+=("-i")
        curl_args+=("-s")
        curl_args+=("-S")
        curl_args+=("--max-time" "$TIMEOUT_SECONDS")
        curl_args+=("--retry" "0")
        
        if [ "$headers_only" = "true" ]; then
            curl_args+=("-I")  # HEAD request
        else
            curl_args+=("-X" "GET")
        fi
        
        curl_args+=("-H" "Authorization: DPoP ${access_token}")
        curl_args+=("-H" "DPoP: ${dpop_proof}")
        curl_args+=("-H" "Accept: ${accept}")
        
        curl_args+=("$url")
        
        local response
        response=$(curl "${curl_args[@]}" 2>&1) || true
        
        # Check for curl errors
        if [ $? -ne 0 ]; then
            last_error="$response"
            
            # Check if retryable
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
        
        # Check HTTP status code
        local http_code
        http_code=$(echo "$response" | head -n 1 | awk '{print $2}')
        
        case "$http_code" in
            200)
                # Success
                break
                ;;
            301|302|303|307|308)
                # Redirect - for now, we don't follow redirects automatically
                log_warn "Redirect detected (${http_code}), not following"
                return $ERROR_NETWORK
                ;;
            401)
                log_error "Unauthorized: Invalid or missing access token/DPoP proof"
                return $ERROR_AUTHENTICATION
                ;;
            403)
                log_error "Forbidden: Access denied"
                return $ERROR_AUTHENTICATION
                ;;
            404)
                log_error "Resource not found: ${url}"
                return $ERROR_RESOURCE_NOT_FOUND
                ;;
            429)
                # Rate limited
                local retry_after
                retry_after=$(echo "$response" | grep -i 'retry-after' | head -1 | awk '{print $2}' || echo "$RETRY_DELAY")
                log_warn "Rate limited. Retrying after ${retry_after}s"
                sleep "$retry_after"
                continue
                ;;
            5*)
                # Server error
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
    # Parse command line arguments
    local sidecar_url="${SOLID_SIDECAR_URL:-$SOLID_SIDECAR_URL_DEFAULT}"
    local access_token="${ACCESS_TOKEN:-}"
    local dpop_proof="${DPOP_PROOF:-}"
    local accept="${ACCEPT:-*/*}"
    local output_file=""
    local headers_only=false
    local quiet=false
    local show_help=false
    
    # Positional argument
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
            --accept)
                accept="$2"
                shift 2
                ;;
            --output)
                output_file="$2"
                shift 2
                ;;
            --headers-only)
                headers_only=true
                shift
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
    
    # Show help if requested
    if [ "$show_help" = "true" ]; then
        grep '^# ' "$0" | sed 's/^# //' | sed 's/^#//'
        return 0
    fi
    
    # Validate required parameters
    validate_required "$resource_uri" "resource URI" || return $?
    validate_required "$access_token" "access_token" || return $?
    validate_required "$dpop_proof" "DPoP proof" || return $?
    
    # Validate URLs
    validate_url "$sidecar_url" "sidecar URL" || return $?
    validate_url "$resource_uri" "resource URI" || return $?
    
    # Set quiet mode
    QUIET="$quiet"
    
    # Resolve full URL
    local url
    url=$(resolve_url "$sidecar_url" "$resource_uri")
    
    log_info "Resolved URL: ${url}"
    log_info "Accept: ${accept}"
    
    # Make request
    local response
    response=$(get_resource "$url" "$access_token" "$dpop_proof" "$accept" "$headers_only") || return $?
    
    # Output result
    if [ -n "$output_file" ]; then
        # Extract body from response (remove headers)
        local body
        body=$(echo "$response" | awk '/^\r$/ {found=1; next} found {print}')
        
        # Securely write to file
        umask 077
        echo "$body" > "$output_file"
        chmod 600 "$output_file"
        log_info "Resource written to $output_file (mode 600)"
        
        # Output headers to stderr
        echo "$response" >&2
    else
        echo "$response"
    fi
    
    return 0
}

# Run main
main "$@"

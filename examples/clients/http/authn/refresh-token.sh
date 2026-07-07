#!/bin/bash
#
# Solid Sidecar HTTP Client Example: Token Refresh
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Authentication
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# Status: STABLE - Production Ready
#
# Description:
#   This script demonstrates refreshing an access token using a refresh token.
#   The refresh token flow is used to obtain new access tokens without requiring
#   the user to re-authenticate.
#
# Security Level: CRITICAL - This script handles credentials and tokens
#
# Usage:
#   ./refresh-token.sh [options]
#
# Options:
#   --issuer ISSUER          OIDC issuer URL (default: $OIDC_ISSUER or https://login.inrupt.com)
#   --client-id ID            Client ID (required, or from $CLIENT_ID)
#   --refresh-token TOKEN    Refresh token to use (required, or from $REFRESH_TOKEN)
#   --scope SCOPE            Requested scopes (default: "openid profile webid")
#   --output FILE            Output tokens to FILE (default: stdout)
#   --quiet                  Suppress progress messages
#   --help                   Show this help
#
# Dependencies:
#   - curl
#   - jq (for JSON parsing)
#
# Security Notes:
#   - NEVER hardcode refresh tokens in scripts
#   - Always use environment variables or secure input
#   - Validate all URLs before sending requests
#   - Never log tokens or sensitive data
#   - Use HTTPS for all production endpoints
#   - Refresh tokens are long-lived credentials - protect them accordingly
#

set -euo pipefail

# --- Configuration ---

# Default values (can be overridden by environment variables)
OIDC_ISSUER_DEFAULT="https://login.inrupt.com"
SCOPES_DEFAULT="openid profile webid"
TIMEOUT_SECONDS=30
MAX_RETRIES=3
RETRY_DELAY=1

# --- Security Constants ---

# Token response timeout
TOKEN_TIMEOUT=30

# --- Error Codes ---

ERROR_INVALID_INPUT=1
ERROR_NETWORK=2
ERROR_AUTHENTICATION=3
ERROR_TOKEN_REFRESH=4
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

validate_url() {
    local url="$1"
    local name="$2"
    
    # Check if empty
    if [ -z "$url" ]; then
        log_error "${name} is required"
        return $ERROR_INVALID_INPUT
    fi
    
    # Check if valid URL (basic check)
    if ! [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/[^\s]*)?$ ]]; then
        log_error "Invalid ${name}: $url"
        return $ERROR_VALIDATION
    fi
    
    return 0
}

validate_required() {
    local value="$1"
    local name="$2"
    
    if [ -z "$value" ]; then
        log_error "${name} is required"
        return $ERROR_INVALID_INPUT
    fi
    
    return 0
}

# --- Token Refresh ---

# Refreshes access token using refresh token
refresh_token() {
    local issuer="$1"
    local client_id="$2"
    local refresh_token="$3"
    local scopes="$4"
    
    local retry_count=0
    local last_error=""
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        retry_count=$((retry_count + 1))
        
        log_info "Token refresh attempt ${retry_count}/${MAX_RETRIES}"
        
        # Build token request
        local token_response
        token_response=$(curl -s -S -f \
            --max-time $TOKEN_TIMEOUT \
            --retry 0 \
            -X POST "${issuer}/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=refresh_token" \
            -d "refresh_token=${refresh_token}" \
            -d "client_id=${client_id}" \
            ${scopes:+-d "scope=${scopes}"} \
            2>&1) || true
        
        # Check for curl errors
        if [ $? -ne 0 ]; then
            last_error="$token_response"
            log_warn "Token refresh failed (attempt ${retry_count}): curl error"
            
            # Check if retryable
            if [[ "$token_response" == *"Connection refused"* ]] || \
               [[ "$token_response" == *"Connection timed out"* ]] || \
               [[ "$token_response" == *"Temporary failure"* ]]; then
                sleep $RETRY_DELAY
                continue
            fi
            
            log_error "Non-retryable curl error: $token_response"
            return $ERROR_NETWORK
        fi
        
        # Check for HTTP errors (curl -f fails on 4xx/5xx)
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time $TOKEN_TIMEOUT \
            -X POST "${issuer}/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=refresh_token" \
            -d "refresh_token=${refresh_token}" \
            -d "client_id=${client_id}" \
            ${scopes:+-d "scope=${scopes}"} \
            2>/dev/null) || echo "000"
        
        case "$http_code" in
            200)
                # Success - parse token response
                ;;
            400)
                log_error "Bad request: Invalid refresh token or client_id"
                return $ERROR_TOKEN_REFRESH
                ;;
            401)
                log_error "Unauthorized: Invalid client_id or refresh token"
                return $ERROR_AUTHENTICATION
                ;;
            403)
                log_error "Forbidden: Access denied"
                return $ERROR_AUTHENTICATION
                ;;
            429)
                # Rate limited - wait and retry
                local retry_after
                retry_after=$(echo "$token_response" | grep -oiP 'retry-after[\s:]+\K[\d]+' | head -1 || echo "$RETRY_DELAY")
                log_warn "Rate limited. Retrying after ${retry_after}s"
                sleep "$retry_after"
                continue
                ;;
            5*)
                # Server error - retry with backoff
                log_warn "Server error ${http_code}. Retrying..."
                sleep $RETRY_DELAY
                continue
                ;;
            *)
                log_error "Unexpected HTTP status: ${http_code}"
                return $ERROR_NETWORK
                ;;
        esac
        
        # Success - parse and validate token response
        break
    done
    
    if [ $retry_count -ge $MAX_RETRIES ]; then
        log_error "Token refresh failed after ${MAX_RETRIES} attempts: ${last_error:-unknown error}"
        return $ERROR_TOKEN_REFRESH
    fi
    
    # Parse token response
    local access_token
    access_token=$(echo "$token_response" | jq -r '.access_token' 2>/dev/null || echo "")
    
    local new_refresh_token
    new_refresh_token=$(echo "$token_response" | jq -r '.refresh_token' 2>/dev/null || echo "")
    
    local expires_in
    expires_in=$(echo "$token_response" | jq -r '.expires_in' 2>/dev/null || echo "3600")
    
    local token_type
    token_type=$(echo "$token_response" | jq -r '.token_type' 2>/dev/null || echo "Bearer")
    
    # Validate required fields
    if [ -z "$access_token" ]; then
        log_error "Token response missing access_token"
        return $ERROR_TOKEN_REFRESH
    fi
    
    # Validate token type
    if [ "$token_type" != "Bearer" ] && [ "$token_type" != "DPoP" ]; then
        log_warn "Unexpected token_type: $token_type"
    fi
    
    # If no new refresh token, use the old one
    if [ -z "$new_refresh_token" ]; then
        new_refresh_token="$refresh_token"
    fi
    
    # Calculate expiration
    local expiry_timestamp
    expiry_timestamp=$(( $(date +%s) + ${expires_in:-3600} ))
    
    # Output tokens
    local output="{\"access_token\":\"$access_token\",\"refresh_token\":\"$new_refresh_token\",\"expires_in\":$expires_in,\"expires_at\":$expiry_timestamp,\"token_type\":\"$token_type\"}"
    
    echo "$output"
    return 0
}

# --- Main ---

main() {
    # Parse command line arguments
    local issuer="${OIDC_ISSUER:-$OIDC_ISSUER_DEFAULT}"
    local client_id="${CLIENT_ID:-}"
    local refresh_token="${REFRESH_TOKEN:-}"
    local scopes="${SCOPES:-$SCOPES_DEFAULT}"
    local output_file=""
    local quiet=false
    local show_help=false
    
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --issuer)
                issuer="$2"
                shift 2
                ;;
            --client-id)
                client_id="$2"
                shift 2
                ;;
            --refresh-token)
                refresh_token="$2"
                shift 2
                ;;
            --scope)
                scopes="$2"
                shift 2
                ;;
            --output)
                output_file="$2"
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
                log_error "Unknown option: $1"
                show_help=true
                return $ERROR_INVALID_INPUT
                ;;
        esac
    done
    
    # Show help if requested
    if [ "$show_help" = "true" ]; then
        grep '^# ' "$0" | sed 's/^# //' | sed 's/^#//'
        return 0
    fi
    
    # Set quiet mode
    QUIET="$quiet"
    
    # Validate required parameters
    validate_required "$client_id" "client_id" || return $?
    validate_required "$refresh_token" "refresh_token" || return $?
    
    # Validate URLs
    validate_url "$issuer" "issuer" || return $?
    
    # Ensure issuer doesn't have trailing slash
    issuer=${issuer%/}
    
    log_info "Starting token refresh"
    log_info "Issuer: $issuer"
    log_info "Client ID: ${client_id:0:8}..."  # Log partial for security
    
    # Refresh token
    local token_response
    token_response=$(refresh_token \
        "$issuer" \
        "$client_id" \
        "$refresh_token" \
        "$scopes") || return $?
    
    # Output result
    if [ -n "$output_file" ]; then
        # Securely write to file (mode 600)
        umask 077
        echo "$token_response" > "$output_file"
        chmod 600 "$output_file"
        log_info "Tokens written to $output_file (mode 600)"
    else
        echo "$token_response"
    fi
    
    log_info "Token refresh successful"
    return 0
}

# Run main
main "$@"

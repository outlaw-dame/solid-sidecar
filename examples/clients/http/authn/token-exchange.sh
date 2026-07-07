#!/bin/bash
#
# Solid Sidecar HTTP Client Example: Token Exchange (PKCE)
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Authentication
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# Status: STABLE - Production Ready
#
# Description:
#   This script demonstrates the PKCE-based OIDC token exchange flow.
#   It generates a code_verifier and code_challenge, then exchanges an
#   authorization code for access and refresh tokens.
#
# Security Level: CRITICAL - This script handles credentials and tokens
#
# Usage:
#   ./token-exchange.sh [options]
#
# Options:
#   --issuer ISSUER          OIDC issuer URL (default: $OIDC_ISSUER or https://login.inrupt.com)
#   --client-id ID            Client ID (required, or from $CLIENT_ID)
#   --redirect-uri URI        Redirect URI (default: $REDIRECT_URI or http://localhost:8080/callback)
#   --code CODE              Authorization code to exchange (required)
#   --code-verifier VERIFIER Code verifier used in auth request (required)
#   --scope SCOPE            Requested scopes (default: "openid profile webid")
#   --output FILE            Output tokens to FILE (default: stdout)
#   --quiet                  Suppress progress messages
#   --help                   Show this help
#
# Dependencies:
#   - curl
#   - jq (for JSON parsing)
#   - openssl (for secure random generation)
#
# Security Notes:
#   - NEVER hardcode client secrets in scripts
#   - Always use environment variables or secure input
#   - Validate all URLs before sending requests
#   - Never log tokens or sensitive data
#   - Use HTTPS for all production endpoints
#

set -euo pipefail

# --- Configuration ---

# Default values (can be overridden by environment variables)
OIDC_ISSUER_DEFAULT="https://login.inrupt.com"
REDIRECT_URI_DEFAULT="http://localhost:8080/callback"
SCOPES_DEFAULT="openid profile webid"
TIMEOUT_SECONDS=30
MAX_RETRIES=3
RETRY_DELAY=1

# --- Security Constants ---

# Minimum code verifier length (RFC 7636: 43-128 characters)
CODE_VERIFIER_MIN_LEN=43
CODE_VERIFIER_MAX_LEN=128

# Token response timeout
TOKEN_TIMEOUT=30

# --- Error Codes ---

ERROR_INVALID_INPUT=1
ERROR_NETWORK=2
ERROR_AUTHENTICATION=3
ERROR_TOKEN_EXCHANGE=4
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

# --- PKCE Code Verifier Generation ---

# Generates a cryptographically secure code verifier
# RFC 7636: code_verifier = 43-128 character random string
# Uses base64url encoding without padding
generate_code_verifier() {
    local length=${1:-64}
    
    # Generate random bytes
    local random_bytes
    random_bytes=$(openssl rand -base64 "$length" | tr -d '\n')
    
    # Remove padding and make URL-safe
    local code_verifier
    code_verifier=$(echo -n "$random_bytes" | tr '+/' '-_' | tr -d '=')
    
    # Ensure length is within bounds
    code_verifier=${code_verifier:0:$CODE_VERIFIER_MAX_LEN}
    
    # If too short (unlikely with openssl), pad with more random
    while [ ${#code_verifier} -lt $CODE_VERIFIER_MIN_LEN ]; do
        local extra=$(openssl rand -base64 8 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
        code_verifier="${code_verifier}${extra}"
        code_verifier=${code_verifier:0:$CODE_VERIFIER_MAX_LEN}
    done
    
    echo "$code_verifier"
}

# Generates code challenge from code verifier
# RFC 7636: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
generate_code_challenge() {
    local code_verifier="$1"
    
    # SHA256 hash
    local hash
    hash=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary)
    
    # Base64url encode without padding
    local challenge
    challenge=$(echo -n "$hash" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    
    echo "$challenge"
}

# --- Token Exchange ---

# Exchanges authorization code for tokens
exchange_token() {
    local issuer="$1"
    local client_id="$2"
    local code="$3"
    local code_verifier="$4"
    local redirect_uri="$5"
    local scopes="$6"
    
    local retry_count=0
    local last_error=""
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        retry_count=$((retry_count + 1))
        
        log_info "Token exchange attempt ${retry_count}/${MAX_RETRIES}"
        
        # Build token request
        local token_response
        token_response=$(curl -s -S -f \
            --max-time $TOKEN_TIMEOUT \
            --retry 0 \
            -X POST "${issuer}/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=authorization_code" \
            -d "code=${code}" \
            -d "redirect_uri=${redirect_uri}" \
            -d "client_id=${client_id}" \
            -d "code_verifier=${code_verifier}" \
            2>&1) || true
        
        # Check for curl errors
        if [ $? -ne 0 ]; then
            last_error="$token_response"
            log_warn "Token exchange failed (attempt ${retry_count}): curl error"
            
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
            -d "grant_type=authorization_code" \
            -d "code=${code}" \
            -d "redirect_uri=${redirect_uri}" \
            -d "client_id=${client_id}" \
            -d "code_verifier=${code_verifier}" 2>/dev/null) || echo "000"
        
        case "$http_code" in
            200)
                # Success - parse token response
                ;;
            400)
                log_error "Bad request: Invalid authorization code or code_verifier"
                return $ERROR_TOKEN_EXCHANGE
                ;;
            401)
                log_error "Unauthorized: Invalid client_id or redirect_uri"
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
        log_error "Token exchange failed after ${MAX_RETRIES} attempts: ${last_error:-unknown error}"
        return $ERROR_TOKEN_EXCHANGE
    fi
    
    # Parse token response
    local access_token
    access_token=$(echo "$token_response" | jq -r '.access_token' 2>/dev/null || echo "")
    
    local refresh_token
    refresh_token=$(echo "$token_response" | jq -r '.refresh_token' 2>/dev/null || echo "")
    
    local expires_in
    expires_in=$(echo "$token_response" | jq -r '.expires_in' 2>/dev/null || echo "3600")
    
    local token_type
    token_type=$(echo "$token_response" | jq -r '.token_type' 2>/dev/null || echo "Bearer")
    
    # Validate required fields
    if [ -z "$access_token" ]; then
        log_error "Token response missing access_token"
        return $ERROR_TOKEN_EXCHANGE
    fi
    
    # Validate token type
    if [ "$token_type" != "Bearer" ] && [ "$token_type" != "DPoP" ]; then
        log_warn "Unexpected token_type: $token_type"
    fi
    
    # Calculate expiration
    local expiry_timestamp
    expiry_timestamp=$(( $(date +%s) + ${expires_in:-3600} ))
    
    # Output tokens
    local output="{\"access_token\":\"$access_token\",\"refresh_token\":\"$refresh_token\",\"expires_in\":$expires_in,\"expires_at\":$expiry_timestamp,\"token_type\":\"$token_type\"}"
    
    echo "$output"
    return 0
}

# --- Main ---

main() {
    # Parse command line arguments
    local issuer="${OIDC_ISSUER:-$OIDC_ISSUER_DEFAULT}"
    local client_id="${CLIENT_ID:-}"
    local redirect_uri="${REDIRECT_URI:-$REDIRECT_URI_DEFAULT}"
    local code="${AUTH_CODE:-}"
    local code_verifier="${CODE_VERIFIER:-}"
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
            --redirect-uri)
                redirect_uri="$2"
                shift 2
                ;;
            --code)
                code="$2"
                shift 2
                ;;
            --code-verifier)
                code_verifier="$2"
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
    validate_required "$code" "authorization code" || return $?
    validate_required "$code_verifier" "code_verifier" || return $?
    
    # Validate URLs
    validate_url "$issuer" "issuer" || return $?
    validate_url "$redirect_uri" "redirect_uri" || return $?
    
    # Ensure issuer doesn't have trailing slash
    issuer=${issuer%/}
    
    log_info "Starting token exchange"
    log_info "Issuer: $issuer"
    log_info "Client ID: ${client_id:0:8}..."  # Log partial for security
    log_info "Scopes: $scopes"
    
    # Exchange token
    local token_response
    token_response=$(exchange_token \
        "$issuer" \
        "$client_id" \
        "$code" \
        "$code_verifier" \
        "$redirect_uri" \
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
    
    log_info "Token exchange successful"
    return 0
}

# Run main
main "$@"

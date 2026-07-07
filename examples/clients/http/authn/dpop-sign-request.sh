#!/bin/bash
#
# Solid Sidecar HTTP Client Example: Sign Request with DPoP
#
# Phase: 27 - SDK/Client Compatibility Layer
# Component: Authentication
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# Status: STABLE - Production Ready
#
# Description:
#   This script demonstrates how to sign an HTTP request with a DPoP proof.
#   It generates a DPoP proof JWT for a given HTTP request and includes it
#   in the request headers along with the access token.
#
# Security Level: CRITICAL - This script handles credentials and cryptographic operations
#
# Usage:
#   ./dpop-sign-request.sh [options] METHOD URL
#
# Options:
#   --access-token TOKEN    Access token (required, or from $ACCESS_TOKEN)
#   --dpop-key FILE         PEM-encoded DPoP private key (required, or from $DPOP_PRIVATE_KEY)
#   --jwk X,Y              Comma-separated JWK x,y coordinates (required, or from $DPOP_JWK)
#   --algorithm ALG         Signing algorithm (default: ES256)
#   --jti JTI              Unique nonce (auto-generated if not provided)
#   --iat IAT              Issued-at timestamp (auto-generated if not provided)
#   --output FILE          Output DPoP proof to FILE (default: stdout)
#   --quiet                Suppress progress messages
#   --help                 Show this help
#
# Arguments:
#   METHOD                 HTTP method (GET, POST, PUT, PATCH, DELETE)
#   URL                    Request URL
#
# Dependencies:
#   - curl (for making requests)
#   - openssl (for cryptographic operations)
#   - jq (for JSON parsing - optional, for pretty printing)
#
# Security Notes:
#   - NEVER hardcode access tokens or private keys in scripts
#   - Always use environment variables or secure input for credentials
#   - Validate all URLs before sending requests
#   - Never log DPoP proofs or access tokens
#   - Use HTTPS for all production endpoints
#

set -euo pipefail

# --- Configuration ---

# Default values
ALGORITHM_DEFAULT="ES256"
TIMEOUT_SECONDS=30
MAX_RETRIES=3
RETRY_DELAY=1

# --- Error Codes ---

ERROR_INVALID_INPUT=1
ERROR_MISSING_CREDENTIALS=2
ERROR_CRYPTO=3
ERROR_NETWORK=4
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
    
    # Basic URL validation
    if ! [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/[^\s]*)?$ ]]; then
        log_error "Invalid ${name}: $url"
        return $ERROR_VALIDATION
    fi
    
    return 0
}

validate_http_method() {
    local method="$1"
    
    case "$method" in
        GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)
            return 0
            ;;
        *)
            log_error "Invalid HTTP method: $method. Must be GET, POST, PUT, PATCH, DELETE, HEAD, or OPTIONS"
            return $ERROR_VALIDATION
            ;;
    esac
}

# --- Base64Url Encoding ---

# Encodes string to Base64Url without padding
base64url_encode() {
    local input="$1"
    echo -n "$input" | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# --- JWT Helper Functions ---

# Creates and signs a JWT
create_jwt() {
    local header_json="$1"
    local claims_json="$2"
    local private_key_pem="$3"
    local algorithm="$4"
    
    # Base64Url encode header and claims
    local header_b64u
    header_b64u=$(base64url_encode "$header_json")
    
    local claims_b64u
    claims_b64u=$(base64url_encode "$claims_json")
    
    # Create signing input
    local signing_input="${header_b64u}.${claims_b64u}"
    
    # Sign based on algorithm
    local signature
    case "$algorithm" in
        ES256|ES384|ES512)
            signature=$(echo -n "$signing_input" | \
                openssl dgst -sha256 -sign "$private_key_pem" -binary | \
                openssl base64 -A | tr '+/' '-_' | tr -d '=')
            ;;
        RS256|RS384|RS512)
            signature=$(echo -n "$signing_input" | \
                openssl dgst -sha256 -sign "$private_key_pem" -binary | \
                openssl base64 -A | tr '+/' '-_' | tr -d '=')
            ;;
        EdDSA)
            signature=$(echo -n "$signing_input" | \
                openssl dgst -sha512 -sign "$private_key_pem" -binary | \
                openssl base64 -A | tr '+/' '-_' | tr -d '=')
            ;;
        *)
            log_error "Unsupported algorithm: $algorithm"
            return $ERROR_CRYPTO
            ;;
    esac
    
    # Create final JWT
    echo "${signing_input}.${signature}"
}

# --- DPoP Proof Generation ---

generate_dpop_proof() {
    local access_token="$1"
    local private_key_pem="$2"
    local jwk_x="$3"
    local jwk_y="$4"
    local crv="$5"
    local algorithm="$6"
    local http_method="$7"
    local http_url="$8"
    local jti="$9"
    local iat="${10}"
    
    # Generate jti if not provided
    if [ -z "$jti" ]; then
        jti=$(openssl rand -base64 16 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
    fi
    
    # Generate iat if not provided
    if [ -z "$iat" ]; then
        iat=$(date +%s)
    fi
    
    # Remove query parameters from URL for htu
    local htu
    htu=${http_url%%\?*}
    
    # Calculate ath (SHA-256 hash of access token, base64url encoded)
    local ath
    if [ -n "$access_token" ]; then
        ath=$(echo -n "$access_token" | openssl dgst -sha256 -binary | base64url_encode)
    else
        ath=""
    fi
    
    # Create JWK
    local jwk
    if [ -n "$crv" ]; then
        jwk="{\"kty\":\"EC\",\"crv\":\"$crv\",\"x\":\"$jwk_x\",\"y\":\"$jwk_y\"}"
    else
        jwk="{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"$jwk_x\",\"y\":\"$jwk_y\"}"
    fi
    
    # Create header
    local header
    header="{\"typ\":\"dpop+jwt\",\"alg\":\"$algorithm\",\"jwk\":$jwk}"
    
    # Create claims
    local claims
    if [ -n "$ath" ]; then
        claims="{\"htm\":\"$http_method\",\"htu\":\"$htu\",\"jti\":\"$jti\",\"iat\":$iat,\"ath\":\"$ath\"}"
    else
        claims="{\"htm\":\"$http_method\",\"htu\":\"$htu\",\"jti\":\"$jti\",\"iat\":$iat}"
    fi
    
    # Create and sign JWT
    create_jwt "$header" "$claims" "$private_key_pem" "$algorithm"
}

# --- Main ---

main() {
    # Parse command line arguments
    local access_token="${ACCESS_TOKEN:-}"
    local dpop_key="${DPOP_PRIVATE_KEY:-}"
    local jwk_x="${DPOP_JWK_X:-}"
    local jwk_y="${DPOP_JWK_Y:-}"
    local algorithm="${DPOP_ALGORITHM:-$ALGORITHM_DEFAULT}"
    local jti="${DPOP_JTI:-}"
    local iat="${DPOP_IAT:-}"
    local output_file=""
    local quiet=false
    local show_help=false
    local make_request=false
    
    # Positional arguments
    local http_method=""
    local http_url=""
    
    # Parse options
    while [ $# -gt 0 ]; do
        case "$1" in
            --access-token)
                access_token="$2"
                shift 2
                ;;
            --dpop-key)
                dpop_key="$2"
                shift 2
                ;;
            --jwk)
                IFS=',' read -r jwk_x jwk_y <<< "$2"
                shift 2
                ;;
            --algorithm)
                algorithm="$2"
                shift 2
                ;;
            --jti)
                jti="$2"
                shift 2
                ;;
            --iat)
                iat="$2"
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
            --make-request)
                make_request=true
                shift
                ;;
            *)
                # Check if it's a known option
                if [[ "$1" == --* ]]; then
                    log_error "Unknown option: $1"
                    show_help=true
                    return $ERROR_INVALID_INPUT
                fi
                # Assume it's the HTTP method
                http_method="$1"
                shift
                # Next should be URL
                if [ $# -gt 0 ]; then
                    http_url="$1"
                    shift
                fi
                ;;
        esac
    done
    
    # Show help if requested or no arguments
    if [ "$show_help" = "true" ] || [ -z "$http_method" ]; then
        if [ "$show_help" != "true" ]; then
            log_error "Missing required arguments: METHOD and URL"
        fi
        grep '^# ' "$0" | sed 's/^# //' | sed 's/^#//'
        return ${show_help:-$ERROR_INVALID_INPUT}
    fi
    
    # Set quiet mode
    QUIET="$quiet"
    
    # Validate required parameters
    validate_required "$access_token" "access_token" || return $?
    validate_required "$dpop_key" "DPoP private key" || return $?
    validate_required "$jwk_x" "JWK x coordinate" || return $?
    validate_required "$jwk_y" "JWK y coordinate" || return $?
    validate_http_method "$http_method" || return $?
    validate_url "$http_url" "URL" || return $?
    
    # Validate private key file exists
    if [ ! -f "$dpop_key" ]; then
        log_error "DPoP private key file not found: $dpop_key"
        return $ERROR_MISSING_CREDENTIALS
    fi
    
    # Validate private key is readable
    if [ ! -r "$dpop_key" ]; then
        log_error "Cannot read DPoP private key file: $dpop_key"
        return $ERROR_MISSING_CREDENTIALS
    fi
    
    log_info "Generating DPoP proof for ${http_method} ${http_url}"
    
    # Generate DPoP proof
    local dpop_proof
    dpop_proof=$(generate_dpop_proof \
        "$access_token" \
        "$dpop_key" \
        "$jwk_x" \
        "$jwk_y" \
        "P-256" \
        "$algorithm" \
        "$http_method" \
        "$http_url" \
        "$jti" \
        "$iat") || return $?
    
    log_info "DPoP proof generated successfully"
    
    # Output DPoP proof
    if [ -n "$output_file" ]; then
        # Securely write to file (mode 600)
        umask 077
        echo "$dpop_proof" > "$output_file"
        chmod 600 "$output_file"
        log_info "DPoP proof written to $output_file (mode 600)"
    else
        echo "$dpop_proof"
    fi
    
    # If make-request flag is set, make the actual request
    if [ "$make_request" = "true" ]; then
        log_info "Making authenticated request..."
        
        local retry_count=0
        local last_error=""
        
        while [ $retry_count -lt $MAX_RETRIES ]; do
            retry_count=$((retry_count + 1))
            
            local response
            response=$(curl -i -s -S \
                --max-time $TIMEOUT_SECONDS \
                --retry 0 \
                -X "$http_method" \
                "$http_url" \
                -H "Authorization: DPoP $access_token" \
                -H "DPoP: $dpop_proof" \
                2>&1) || true
            
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
            
            # Success - output response
            echo "$response"
            break
        done
        
        if [ $retry_count -ge $MAX_RETRIES ]; then
            log_error "Request failed after ${MAX_RETRIES} attempts: ${last_error:-unknown error}"
            return $ERROR_NETWORK
        fi
    fi
    
    return 0
}

# Run main
main "$@"

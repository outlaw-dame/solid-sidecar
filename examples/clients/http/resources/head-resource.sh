#!/bin/bash
#
# Solid Sidecar - HEAD Resource Example
# Phase: 27 - SDK/Client Compatibility Layer
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# License: MIT
#
# This script demonstrates how to retrieve only the metadata (headers) of a
# Solid resource using the HEAD method.
#
# HEAD is useful for:
# - Checking if a resource exists
# - Getting resource metadata (Content-Type, ETag, Last-Modified)
# - Performing conditional operations
# - Reducing bandwidth usage
#
# Usage:
#   ./head-resource.sh <resource-uri> [base-url] [access-token] [dpop-proof]
#
# Example:
#   ./head-resource.sh /profile/card https://localhost:8443 "$ACCESS_TOKEN" "$DPOP_PROOF"
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

# Default base URL (can be overridden by argument)
DEFAULT_BASE_URL="https://localhost:8443"

# Default headers
CONTENT_TYPE_HEADER="Accept: text/turtle, application/ld+json, */*;q=0.1"

# Timeout in seconds
TIMEOUT=30

# ============================================================================
# Color Output
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# Logging Functions
# ============================================================================

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_header() {
  echo -e "\n${BLUE}=== $1 ===${NC}"
}

log_response() {
  local status=$1
  local message=$2
  
  if [[ $status == 2* ]]; then
    echo -e "${GREEN}[SUCCESS]${NC} $message"
  elif [[ $status == 4* ]]; then
    echo -e "${RED}[CLIENT ERROR]${NC} $message"
  elif [[ $status == 5* ]]; then
    echo -e "${RED}[SERVER ERROR]${NC} $message"
  else
    echo -e "${YELLOW}[UNKNOWN]${NC} $message"
  fi
}

# ============================================================================
# Validation Functions
# ============================================================================

# Validate that a URL is safe to request (SSRF prevention)
validate_url() {
  local url="$1"
  
  # Check if URL is empty
  if [[ -z "$url" ]]; then
    log_error "URL cannot be empty"
    return 1
  fi
  
  # Check for disallowed schemes
  if [[ "$url" =~ ^(file|ftp|gopher|data|javascript|mailto|telnet): ]]; then
    log_error "Disallowed URL scheme: $url"
    return 1
  fi
  
  # Check for credentials in URL
  if [[ "$url" =~ ://[^:]+:[^@]+@ ]]; then
    log_error "URL contains credentials: $url"
    return 1
  fi
  
  return 0
}

# Validate resource URI for IDOR prevention
validate_resource_uri() {
  local resource_uri="$1"
  
  # Check for path traversal
  if [[ "$resource_uri" =~ \.\. ]]; then
    log_error "Path traversal detected in resource URI: $resource_uri"
    return 1
  fi
  
  # Check for null bytes
  if [[ "$resource_uri" =~ $'\0' ]]; then
    log_error "Null byte detected in resource URI: $resource_uri"
    return 1
  fi
  
  return 0
}

# ============================================================================
# Main Function
# ============================================================================

main() {
  local resource_uri="${1:-}"
  local base_url="${2:-$DEFAULT_BASE_URL}"
  local access_token="${3:-}"
  local dpop_proof="${4:-}"
  
  # Validate inputs
  if [[ -z "$resource_uri" ]]; then
    log_error "Resource URI is required"
    echo "Usage: $0 <resource-uri> [base-url] [access-token] [dpop-proof]"
    echo "Example: $0 /profile/card https://localhost:8443 \"\$ACCESS_TOKEN\" \"\$DPOP_PROOF\""
    exit 1
  fi
  
  # Validate resource URI
  if ! validate_resource_uri "$resource_uri"; then
    exit 1
  fi
  
  # Validate base URL
  if ! validate_url "$base_url"; then
    exit 1
  fi
  
  # Construct full URL
  local full_url
  if [[ "$resource_uri" == http://* ]] || [[ "$resource_uri" == https://* ]]; then
    full_url="$resource_uri"
  else
    # Remove trailing slash from base URL
    base_url="${base_url%/}"
    # Remove leading slash from resource URI
    resource_uri="${resource_uri#/}"
    full_url="${base_url}/${resource_uri}"
  fi
  
  log_info "Resource URI: $resource_uri"
  log_info "Base URL: $base_url"
  log_info "Full URL: $full_url"
  
  # Build headers
  local headers=()
  headers+=("-H" "$CONTENT_TYPE_HEADER")
  
  # Add authentication headers if provided
  if [[ -n "$access_token" ]]; then
    headers+=("-H" "Authorization: DPoP ${access_token}")
    log_info "Using DPoP authentication"
  fi
  
  if [[ -n "$dpop_proof" ]]; then
    headers+=("-H" "DPoP: ${dpop_proof}")
    log_info "Using DPoP proof"
  fi
  
  # Log request
  log_header "HEAD Request"
  echo "URL: $full_url"
  echo "Method: HEAD"
  
  # Make the HEAD request using curl
  log_info "Sending HEAD request..."
  
  local response
  local http_code
  local headers_output
  
  response=$(curl -sS \
    -X HEAD \
    "${headers[@]}" \
    -w "\n%{http_code}" \
    --max-time "$TIMEOUT" \
    "$full_url" 2>&1 || true)
  
  # Extract HTTP status code (last line)
  http_code=$(echo "$response" | tail -n1)
  
  # Extract headers (all lines except last)
  headers_output=$(echo "$response" | head -n -1)
  
  # Log response
  echo ""
  log_header "HEAD Response"
  log_response "$http_code" "$(echo "$headers_output" | head -n1 | tr -d '\r')"
  
  echo ""
  echo "Headers:"
  echo "-------"
  
  if [[ -n "$headers_output" ]]; then
    # Parse and display headers
    while IFS= read -r line; do
      # Skip empty lines
      [[ -z "$line" ]] && continue
      
      # Remove carriage returns
      line="${line%$'\r'}"
      
      # Display header
      echo "  $line"
      
      # Extract and highlight important headers
      if [[ "$line" =~ ^ETag: ]]; then
        log_info "ETag: ${line#ETag: }"
      elif [[ "$line" =~ ^Last-Modified: ]]; then
        log_info "Last-Modified: ${line#Last-Modified: }"
      elif [[ "$line" =~ ^Content-Type: ]]; then
        log_info "Content-Type: ${line#Content-Type: }"
      elif [[ "$line" =~ ^Content-Length: ]]; then
        log_info "Content-Length: ${line#Content-Length: }"
      elif [[ "$line" =~ ^Link: ]]; then
        log_info "Link: ${line#Link: }"
      fi
    done <<< "$headers_output"
  else
    log_warn "No headers received"
  fi
  
  echo ""
  
  # Check for errors
  case "$http_code" in
    200)
      log_info "Resource exists and metadata was retrieved"
      ;;
    401)
      log_error "Unauthorized - Check your access token and DPoP proof"
      exit 1
      ;;
    403)
      log_error "Forbidden - Access denied by policy"
      exit 1
      ;;
    404)
      log_error "Not Found - Resource does not exist"
      exit 1
      ;;
    405)
      log_error "Method Not Allowed - HEAD not supported for this resource"
      exit 1
      ;;
    500|502|503|504)
      log_error "Server Error - Try again later"
      exit 1
      ;;
    *)
      if [[ "$http_code" == 3* ]]; then
        log_warn "Redirect - Follow the redirect or use -L flag with curl"
      else
        log_warn "Unexpected status code: $http_code"
      fi
      ;;
  esac
  
  # Return status code
  return 0
}

# ============================================================================
# Entry Point
# ============================================================================

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

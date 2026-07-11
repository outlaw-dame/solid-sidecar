#!/bin/bash
#
# Solid Sidecar - PATCH Resource Example
# Phase: 27 - SDK/Client Compatibility Layer
# Version: v1.0.0
# Created: 2026-07-07
# Author: Mistral Vibe
# License: MIT
#
# This script demonstrates how to perform a partial update on a Solid resource
# using the PATCH method with SPARQL Update.
#
# PATCH is used for:
# - Modifying specific triples in an RDF resource
# - Adding new statements without replacing the entire resource
# - Deleting specific statements
# - Updating RDF data atomically
#
# Usage:
#   ./patch-resource.sh <resource-uri> <sparql-update-file> [base-url] [access-token] [dpop-proof] [if-match]
#
# Example:
#   ./patch-resource.sh /profile/card update.sparql https://localhost:8443 "$ACCESS_TOKEN" "$DPOP_PROOF" "$ETAG"
#
# Where update.sparql contains SPARQL Update queries like:
#   PREFIX foaf: <http://xmlns.com/foaf/0.1/>
#   INSERT DATA { <https://example.org/profile/card> foaf:name "New Name" }
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

# Default base URL (can be overridden by argument)
DEFAULT_BASE_URL="https://localhost:8443"

# Default headers
CONTENT_TYPE_HEADER="Content-Type: application/sparql-update"
ACCEPT_HEADER="Accept: text/turtle, application/ld+json"

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
  
  if [[ -z "$url" ]]; then
    log_error "URL cannot be empty"
    return 1
  fi
  
  if [[ "$url" =~ ^(file|ftp|gopher|data|javascript|mailto|telnet): ]]; then
    log_error "Disallowed URL scheme: $url"
    return 1
  fi
  
  if [[ "$url" =~ ://[^:]+:[^@]+@ ]]; then
    log_error "URL contains credentials: $url"
    return 1
  fi
  
  return 0
}

# Validate resource URI for IDOR prevention
validate_resource_uri() {
  local resource_uri="$1"
  
  if [[ "$resource_uri" =~ \.\. ]]; then
    log_error "Path traversal detected in resource URI: $resource_uri"
    return 1
  fi
  
  if [[ "$resource_uri" =~ $'\0' ]]; then
    log_error "Null byte detected in resource URI: $resource_uri"
    return 1
  fi
  
  return 0
}

# Validate SPARQL Update file
validate_sparql_file() {
  local file="$1"
  
  if [[ ! -f "$file" ]]; then
    log_error "SPARQL Update file not found: $file"
    return 1
  fi
  
  if [[ ! -r "$file" ]]; then
    log_error "SPARQL Update file not readable: $file"
    return 1
  fi
  
  return 0
}

# ============================================================================
# Main Function
# ============================================================================

main() {
  local resource_uri="${1:-}"
  local sparql_file="${2:-}"
  local base_url="${3:-$DEFAULT_BASE_URL}"
  local access_token="${4:-}"
  local dpop_proof="${5:-}"
  local if_match="${6:-}"
  
  # Validate inputs
  if [[ -z "$resource_uri" ]]; then
    log_error "Resource URI is required"
    echo "Usage: $0 <resource-uri> <sparql-update-file> [base-url] [access-token] [dpop-proof] [if-match]"
    echo "Example: $0 /profile/card update.sparql https://localhost:8443 \"\$ACCESS_TOKEN\" \"\$DPOP_PROOF\" \"\$ETAG\""
    exit 1
  fi
  
  if [[ -z "$sparql_file" ]]; then
    log_error "SPARQL Update file is required"
    echo "Usage: $0 <resource-uri> <sparql-update-file> [base-url] [access-token] [dpop-proof] [if-match]"
    exit 1
  fi
  
  # Validate resource URI
  if ! validate_resource_uri "$resource_uri"; then
    exit 1
  fi
  
  # Validate SPARQL file
  if ! validate_sparql_file "$sparql_file"; then
    exit 1
  fi
  
  # Validate base URL
  if ! validate_url "$base_url"; then
    exit 1
  fi
  
  # Read SPARQL Update content
  local sparql_update
  sparql_update=$(cat "$sparql_file")
  
  # Construct full URL
  local full_url
  if [[ "$resource_uri" == http://* ]] || [[ "$resource_uri" == https://* ]]; then
    full_url="$resource_uri"
  else
    base_url="${base_url%/}"
    resource_uri="${resource_uri#/}"
    full_url="${base_url}/${resource_uri}"
  fi
  
  log_info "Resource URI: $resource_uri"
  log_info "Base URL: $base_url"
  log_info "Full URL: $full_url"
  log_info "SPARQL Update file: $sparql_file"
  
  # Build headers
  local headers=()
  headers+=("-H" "$CONTENT_TYPE_HEADER")
  headers+=("-H" "$ACCEPT_HEADER")
  
  # Add authentication headers if provided
  if [[ -n "$access_token" ]]; then
    headers+=("-H" "Authorization: DPoP ${access_token}")
    log_info "Using DPoP authentication"
  fi
  
  if [[ -n "$dpop_proof" ]]; then
    headers+=("-H" "DPoP: ${dpop_proof}")
    log_info "Using DPoP proof"
  fi
  
  # Add If-Match header for conditional PATCH
  if [[ -n "$if_match" ]]; then
    headers+=("-H" "If-Match: \"${if_match}\"")
    log_info "Using If-Match: \"${if_match}\""
  fi
  
  # Log request
  log_header "PATCH Request"
  echo "URL: $full_url"
  echo "Method: PATCH"
  echo "Content-Type: application/sparql-update"
  if [[ -n "$if_match" ]]; then
    echo "If-Match: \"${if_match}\""
  fi
  echo ""
  log_info "SPARQL Update:"
  echo "$sparql_update"
  echo ""
  
  # Make the PATCH request using curl
  log_info "Sending PATCH request..."
  
  local response
  local http_code
  local body
  
  response=$(curl -sS \
    -X PATCH \
    "${headers[@]}" \
    -d "$sparql_update" \
    -w "\n%{http_code}" \
    --max-time "$TIMEOUT" \
    "$full_url" 2>&1 || true)
  
  # Extract HTTP status code (last line)
  http_code=$(echo "$response" | tail -n1)
  
  # Extract body (all lines except last)
  body=$(echo "$response" | head -n -1)
  
  # Log response
  echo ""
  log_header "PATCH Response"
  log_response "$http_code" "$(echo "$body" | head -n1 | tr -d '\r')"
  
  echo ""
  
  # Display response body if any
  if [[ -n "$body" ]]; then
    echo "Response Body:"
    echo "-------------"
    echo "$body"
    echo ""
  fi
  
  # Check for errors
  case "$http_code" in
    200|204)
      log_info "PATCH successful"
      ;;
    201)
      log_info "PATCH successful - Resource created"
      ;;
    400)
      log_error "Bad Request - Invalid SPARQL Update syntax"
      exit 1
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
    409)
      log_error "Conflict - PATCH would create a conflict"
      exit 1
      ;;
    412)
      log_error "Precondition Failed - If-Match header doesn't match current ETag"
      exit 1
      ;;
    413)
      log_error "Payload Too Large - SPARQL Update is too large"
      exit 1
      ;;
    415)
      log_error "Unsupported Media Type - Content-Type must be application/sparql-update"
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
  
  return 0
}

# ============================================================================
# Entry Point
# ============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

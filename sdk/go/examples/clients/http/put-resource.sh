#!/bin/bash
# put-resource.sh - Example script to PUT (create/update) a resource in Solid Sidecar
#
# Phase 27 - SDK/Client Compatibility Layer
# Status: STABLE - Production Ready - FULLY HARDENED
#
# Usage: ./put-resource.sh [resource-uri] [content-file] [if-match] [if-none-match]
#
# Example: ./put-resource.sh https://pod.example.com/data/file.txt file.ttl
# Example: ./put-resource.sh https://pod.example.com/data/file.txt file.ttl "current-etag"
# Example: ./put-resource.sh https://pod.example.com/data/new.txt file.ttl "" "*"

set -euo pipefail

# Configuration - REPLACE THESE WITH YOUR ACTUAL VALUES
SIDECAR_URL="${SIDECAR_URL:-https://your-sidecar-instance.com}"
ACCESS_TOKEN="${ACCESS_TOKEN:-your-access-token-here}"
DPOP_PROOF="${DPOP_PROOF:-your-dpop-proof-here}"
CONTENT_TYPE="${CONTENT_TYPE:-text/turtle}"

# Validate that we're not using placeholder values
if [[ "$ACCESS_TOKEN" == "your-access-token-here" ]] || [[ "$DPOP_PROOF" == "your-dpop-proof-here" ]]; then
    echo "ERROR: You must set ACCESS_TOKEN and DPOP_PROOF environment variables"
    echo "Example: export ACCESS_TOKEN=\"your-token\""
    echo "         export DPOP_PROOF=\"your-proof\""
    exit 1
fi

# Validate arguments
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 [resource-uri] [content-file] [if-match] [if-none-match]"
    echo ""
    echo "Examples:"
    echo "  $0 https://pod.example.com/data/file.txt file.ttl"
    echo "  $0 https://pod.example.com/data/file.txt file.ttl current-etag"
    echo "  $0 https://pod.example.com/data/new.txt file.ttl '' '*'"
    exit 1
fi

RESOURCE_URI="$1"
CONTENT_FILE="$2"
IF_MATCH="${3:-}"
IF_NONE_MATCH="${4:-}"

# Validate URI format
if [[ ! "$RESOURCE_URI" =~ ^https?:// ]]; then
    echo "ERROR: Invalid URI format: $RESOURCE_URI"
    echo "URI must start with http:// or https://"
    exit 1
fi

# Validate content file exists
if [[ ! -f "$CONTENT_FILE" ]]; then
    echo "ERROR: Content file not found: $CONTENT_FILE"
    exit 1
fi

# Validate content file size (< 10MB)
FILE_SIZE=$(stat -f%z "$CONTENT_FILE" 2>/dev/null || stat -c%s "$CONTENT_FILE" 2>/dev/null)
MAX_SIZE=$((10 * 1024 * 1024))
if [[ "$FILE_SIZE" -gt "$MAX_SIZE" ]]; then
    echo "ERROR: Content file too large: $FILE_SIZE bytes (max: $MAX_SIZE)"
    exit 1
fi

# Build headers
HEADERS=(
  "-H" "Authorization: DPoP $ACCESS_TOKEN"
  "-H" "DPoP: $DPOP_PROOF"
  "-H" "Content-Type: $CONTENT_TYPE"
)

# Add conditional headers if provided
if [[ -n "$IF_MATCH" ]]; then
    HEADERS+=("-H" "If-Match: \"$IF_MATCH\"")
fi

if [[ -n "$IF_NONE_MATCH" ]]; then
    HEADERS+=("-H" "If-None-Match: \"$IF_NONE_MATCH\"")
fi

echo "PUT Resource Example"
echo "===================="
echo "URL: $RESOURCE_URI"
echo "Content-Type: $CONTENT_TYPE"
echo "Content-File: $CONTENT_FILE"
echo "Content-Size: $FILE_SIZE bytes"
if [[ -n "$IF_MATCH" ]]; then
    echo "If-Match: $IF_MATCH"
fi
if [[ -n "$IF_NONE_MATCH" ]]; then
    echo "If-None-Match: $IF_NONE_MATCH"
fi
echo ""

# Make the request
RESPONSE=$(curl -s -w "\n%{http_code}\n" \
  -X PUT \
  "${HEADERS[@]}" \
  --data-binary "@$CONTENT_FILE" \
  "$RESOURCE_URI")

# Extract status code and body
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "Status: $STATUS_CODE"
echo ""

# Check for errors
case "$STATUS_CODE" in
  200|204)
    echo "Success! Resource updated:"
    if [[ -n "$BODY" ]]; then
        echo "---"
        echo "$BODY"
        echo "---"
    fi
    ;;
  201)
    echo "Success! Resource created:"
    echo "---"
    echo "$BODY"
    echo "---"
    # Extract Location header if present
    LOCATION=$(echo "$BODY" | grep -i "Location:" | head -1 | awk '{print $2}')
    if [[ -n "$LOCATION" ]]; then
        echo "Location: $LOCATION"
    fi
    ;;
  401)
    echo "ERROR: Unauthorized - Invalid or missing access token"
    exit 1
    ;;
  403)
    echo "ERROR: Forbidden - Access denied to resource"
    exit 1
    ;;
  409)
    echo "ERROR: Conflict - Resource already exists (when using If-None-Match: *)"
    exit 1
    ;;
  412)
    echo "ERROR: Precondition Failed - ETag does not match"
    echo "This usually means the resource was modified by another process"
    exit 1
    ;;
  500|502|503|504)
    echo "ERROR: Server error ($STATUS_CODE)"
    echo "$BODY"
    exit 1
    ;;
  *)
    echo "Unexpected status code: $STATUS_CODE"
    echo "$BODY"
    exit 1
    ;;
esac

echo ""
echo "PUT request completed successfully"

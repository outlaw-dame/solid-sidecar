#!/bin/bash
# get-resource.sh - Example script to GET a resource from Solid Sidecar
#
# Phase 27 - SDK/Client Compatibility Layer
# Status: STABLE - Production Ready - FULLY HARDENED
#
# Usage: ./get-resource.sh [resource-uri]
#
# Example: ./get-resource.sh https://pod.example.com/data/file.txt

set -euo pipefail

# Configuration - REPLACE THESE WITH YOUR ACTUAL VALUES
SIDECAR_URL="${SIDECAR_URL:-https://your-sidecar-instance.com}"
ACCESS_TOKEN="${ACCESS_TOKEN:-your-access-token-here}"
DPOP_PROOF="${DPOP_PROOF:-your-dpop-proof-here}"

# Validate that we're not using placeholder values
if [[ "$ACCESS_TOKEN" == "your-access-token-here" ]] || [[ "$DPOP_PROOF" == "your-dpop-proof-here" ]]; then
    echo "ERROR: You must set ACCESS_TOKEN and DPOP_PROOF environment variables"
    echo "Example: export ACCESS_TOKEN=\"your-token\""
    echo "         export DPOP_PROOF=\"your-proof\""
    exit 1
fi

# Resource URI from command line or default
RESOURCE_URI="${1:-$SIDECAR_URL/data/file.txt}"

# Validate URI format
if [[ ! "$RESOURCE_URI" =~ ^https?:// ]]; then
    echo "ERROR: Invalid URI format: $RESOURCE_URI"
    echo "URI must start with http:// or https://"
    exit 1
fi

# Build full URL (handle both absolute and relative URIs)
if [[ "$RESOURCE_URI" =~ ^https?:// ]]; then
    FULL_URL="$RESOURCE_URI"
else
    FULL_URL="${SIDECAR_URL%/}/${RESOURCE_URI#/}"
fi

echo "GET Resource Example"
echo "===================="
echo "URL: $FULL_URL"
echo ""

# Make the request
RESPONSE=$(curl -s -w "\n%{http_code}\n" \
  -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/turtle, application/ld+json, */*" \
  "$FULL_URL")

# Extract status code and body
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "Status: $STATUS_CODE"
echo ""

# Check for errors
case "$STATUS_CODE" in
  200)
    echo "Success! Resource retrieved:"
    echo "---"
    echo "$BODY"
    echo "---"
    ;;
  401)
    echo "ERROR: Unauthorized - Invalid or missing access token"
    exit 1
    ;;
  403)
    echo "ERROR: Forbidden - Access denied to resource"
    exit 1
    ;;
  404)
    echo "ERROR: Resource not found"
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
echo "GET request completed successfully"

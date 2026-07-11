# Migration Check Examples

This directory contains examples for checking migration compatibility between CSS and the native runtime.

## Overview

Migration checks are essential when transitioning from a CSS-backed deployment to the native runtime. These examples demonstrate how to verify that your resources, policies, and data will be preserved correctly during migration.

## Prerequisites

- A running solid-sidecar instance in shadow mode
- Access to a CSS instance for comparison
- Valid authentication credentials

## Examples

### 1. Resource Inventory Check

Verify that all resources from CSS are present in the sidecar:

```bash
# Get resource list from CSS
curl -X GET "https://css.example.com/" \
  -H "Authorization: Bearer $CSS_TOKEN" \
  -H "Accept: application/json" > css_resources.json

# Get resource list from sidecar
curl -X GET "https://sidecar.example.com/" \
  -H "Authorization: Bearer $SIDECAR_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: application/json" > sidecar_resources.json

# Compare resource lists
diff css_resources.json sidecar_resources.json
```

### 2. Policy Compatibility Check

Verify that WAC/ACP policies are correctly parsed and enforced:

```bash
# Get a resource with its ACL from CSS
curl -X GET "https://css.example.com/resource.ttl" \
  -H "Authorization: Bearer $CSS_TOKEN" > css_resource_with_acl.ttl

# Get the same resource from sidecar
curl -X GET "https://sidecar.example.com/resource.ttl" \
  -H "Authorization: Bearer $SIDECAR_TOKEN" \
  -H "DPoP: $DPOP_PROOF" > sidecar_resource_with_acl.ttl

# Compare the ACLs
# Note: The sidecar may format policies differently, but the semantics should be equivalent
```

### 3. Authorization Decision Comparison

The sidecar provides a CSS comparison mode to verify that authorization decisions match CSS:

```bash
# Enable shadow mode with CSS comparison
# This requires the sidecar to be configured with CSS_COMPARISON_ENABLED=true

# Make a request through the sidecar
curl -X GET "https://sidecar.example.com/protected-resource" \
  -H "Authorization: Bearer $TOKEN" \
  -H "DPoP: $DPOP_PROOF"

# Check the response headers for comparison results
# X-Sidecar-CSS-Comparison: match|mismatch
# X-Sidecar-CSS-Decision: allow|deny
# X-Sidecar-Native-Decision: allow|deny
```

### 4. Data Integrity Check

Verify that resource content has not been corrupted:

```bash
# Get checksum from CSS (if available)
# Or compute locally from a known-good copy
sha256sum known_good_resource.ttl

# Get resource from sidecar
curl -X GET "https://sidecar.example.com/resource.ttl" \
  -H "Authorization: Bearer $SIDECAR_TOKEN" \
  -H "DPoP: $DPOP_PROOF" > sidecar_resource.ttl

# Compute checksum of sidecar resource
sha256sum sidecar_resource.ttl

# Compare checksums
# They should match if no data corruption occurred
```

### 5. Metadata Consistency Check

Verify that resource metadata (ETags, Last-Modified, etc.) is consistent:

```bash
# Get resource with metadata from CSS
curl -X HEAD "https://css.example.com/resource.ttl" \
  -H "Authorization: Bearer $CSS_TOKEN" \
  -v 2>&1 | grep -E "ETag|Last-Modified|Content-Type|Content-Length"

# Get same resource from sidecar
curl -X HEAD "https://sidecar.example.com/resource.ttl" \
  -H "Authorization: Bearer $SIDECAR_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -v 2>&1 | grep -E "ETag|Last-Modified|Content-Type|Content-Length"
```

### 6. Conditional Write Compatibility

Verify that conditional writes work the same way:

```bash
# Get current ETag from sidecar
ETAG=$(curl -X HEAD "https://sidecar.example.com/resource.ttl" \
  -H "Authorization: Bearer $SIDECAR_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -s -I | grep -oP '(?<=ETag: ).*' | tr -d '\r')

# Try to update with correct ETag
echo "new content" | curl -X PUT "https://sidecar.example.com/resource.ttl" \
  -H "Authorization: Bearer $SIDECAR_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "If-Match: $ETAG" \
  -H "Content-Type: text/turtle" \
  --data-binary @-

# Should succeed with 200 or 204

# Try to update with wrong ETag
echo "different content" | curl -X PUT "https://sidecar.example.com/resource.ttl" \
  -H "Authorization: Bearer $SIDECAR_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "If-Match: wrong-etag" \
  -H "Content-Type: text/turtle" \
  --data-binary @-

# Should fail with 412 Precondition Failed
```

## Migration Check Script

For automated migration checks, see the migration tooling in Phase 25.

## Notes

- Always perform migration checks in a staging environment before production
- The sidecar should be in shadow mode during migration verification
- Compare a representative sample of resources, not just a few test resources
- Pay special attention to resources with complex ACLs or ACP policies
- Verify that container listings (e.g., for `/`) return the same resources

# Solid Client Compatibility Recipes

This directory contains compatibility recipes for using common Solid JavaScript clients with the solid-sidecar.

## Overview

The solid-sidecar is designed to be compatible with standard Solid protocol implementations. This document provides guidance on using popular Solid client libraries with the sidecar.

## Compatibility Matrix

| Client Library | Status | Notes |
|---------------|--------|-------|
| [@inrupt/solid-client-authn-js](https://github.com/inrupt/solid-client-authn-js) | ✅ Compatible | Works with DPoP authentication |
| [@inrupt/solid-client-js](https://github.com/inrupt/solid-client-js) | ✅ Compatible | Resource CRUD operations |
| [solid-auth-client](https://github.com/solid/solid-auth-client) | ✅ Compatible | Legacy auth library |
| [rdflib.js](https://github.com/linkeddata/rdflib.js) | ✅ Compatible | RDF operations |
| [@rdfjs/data-model](https://github.com/rdfjs/data-model) | ✅ Compatible | RDF data structures |

## Configuration

### Base URL

When using a client library with the sidecar, set the base URL to the sidecar endpoint:

```javascript
// For development
const sidecarUrl = 'http://localhost:8080';

// For production
const sidecarUrl = 'https://sidecar.yourdomain.com';
```

### Authentication

The sidecar requires DPoP-bound access tokens. Most modern Solid clients support this automatically.

## Recipe: Using @inrupt/solid-client-authn-js

### Installation

```bash
npm install @inrupt/solid-client-authn-js
```

### Usage

```javascript
import { 
  getDefaultSession, 
  fetch, 
  login, 
  handleIncomingRedirect 
} from '@inrupt/solid-client-authn-js';

// Initialize session
const session = getDefaultSession();

// Login (redirect flow)
async function loginToSidecar() {
  const oidcIssuer = 'https://your-oidc-issuer.com';
  const clientId = 'https://your-app.com';
  const redirectUrl = new URL('/redirect', window.location.origin).toString();

  await login({
    oidcIssuer,
    redirectUrl,
    clientId,
    // The sidecar supports DPoP by default
    tokenType: 'DPoP',
  });
}

// Handle redirect after login
if (window.location.href.includes('/redirect')) {
  await handleIncomingRedirect({
    url: window.location.href,
    restorePreviousSession: true,
  });
}

// Make authenticated requests
async function fetchResource(resourceUrl) {
  const response = await fetch(resourceUrl, {
    // The session automatically adds Authorization and DPoP headers
    credentials: 'include',
    headers: {
      // Your custom headers
    },
  });
  return response;
}
```

## Recipe: Using @inrupt/solid-client-js

### Installation

```bash
npm install @inrupt/solid-client-js
```

### Usage

```javascript
import { 
  getSolidDataset, 
  getThing, 
  saveSolidDatasetAt, 
  createSolidDataset,
  createThing,
  addUrl,
  setThing,
  getFile,
  saveFileInContainer,
  deleteFile 
} from '@inrupt/solid-client-js';
import { fetch } from '@inrupt/solid-client-authn-js';

// Fetch a resource
async function readResource(resourceUrl) {
  const dataset = await getSolidDataset(resourceUrl, { fetch });
  const thing = getThing(dataset, 'https://example.com/resource#thing');
  
  // Access properties
  const name = getUrl(thing, 'http://schema.org/name');
  
  return { dataset, thing, name };
}

// Create a new resource
async function createNewResource(containerUrl, filename, content, contentType) {
  const newDataset = createSolidDataset();
  const thing = createThing({ name: 'new-thing' });
  const updatedDataset = setThing(newDataset, thing);
  
  await saveSolidDatasetAt(containerUrl + filename, updatedDataset, { fetch });
}

// Upload a file
async function uploadFile(containerUrl, file) {
  const savedFile = await saveFileInContainer(
    containerUrl,
    file,
    { 
      fetch,
      slug: file.name,
      contentType: file.type 
    }
  );
  return savedFile;
}

// Delete a resource
async function deleteResource(resourceUrl) {
  await deleteFile(resourceUrl, { fetch });
}
```

## Recipe: Using rdflib.js

### Installation

```bash
npm install rdflib
```

### Usage

```javascript
import rdf from 'rdflib';

// Create a graph
const graph = rdf.graph();

// Add triples
const subject = rdf.namedNode('https://example.com/resource#me');
const name = rdf.literal('John Doe');
const type = rdf.namedNode('http://xmlns.com/foaf/0.1/Person');

graph.add(
  subject, 
  rdf.namedNode('http://xmlns.com/foaf/0.1/name'), 
  name,
  graph
);

graph.add(
  subject, 
  rdf.namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'), 
  type,
  graph
);

// Serialize to Turtle
const turtle = rdf.serialize(null, graph, null, 'text/turtle');
console.log(turtle);

// Parse Turtle
async function parseTurtle(url, fetch) {
  const response = await fetch(url, {
    headers: {
      Accept: 'text/turtle',
    },
  });
  const text = await response.text();
  const parsedGraph = rdf.graph();
  rdf.parse(text, parsedGraph, url, 'text/turtle');
  return parsedGraph;
}
```

## Recipe: Direct Fetch API Usage

For applications not using a Solid-specific client library:

```javascript
async function fetchWithDPoP(url, options = {}) {
  // Get access token from your auth library
  const accessToken = localStorage.getItem('accessToken');
  
  // Generate DPoP proof (using your DPoP library)
  const dpopProof = await generateDPoPProof({
    url,
    method: options.method || 'GET',
    accessToken,
    keyPair: localStorage.getItem('keyPair'),
  });

  // Make request with both headers
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `DPoP ${accessToken}`,
      DPoP: dpopProof,
    },
  });

  return response;
}

// Usage
async function getResource(url) {
  const response = await fetchWithDPoP(url);
  return response;
}
```

## Known Compatibility Issues

### Issue: CORS Preflight

**Symptom**: Preflight requests (OPTIONS) fail with 401 or 403.

**Solution**: The sidecar handles CORS preflight requests. Ensure:
1. The `Origin` header is included in requests
2. The sidecar is configured with proper CORS settings
3. The client library is not stripping necessary headers

### Issue: DPoP Not Supported

**Symptom**: Client library doesn't support DPoP authentication.

**Solution**: Use a modern client library like `@inrupt/solid-client-authn-js` that supports DPoP, or implement DPoP proof generation separately.

### Issue: ETag Handling

**Symptom**: Conditional requests (If-Match, If-None-Match) don't work as expected.

**Solution**: The sidecar fully supports ETags. Ensure your client:
1. Reads the ETag from response headers
2. Includes it in subsequent conditional requests
3. Handles 412 Precondition Failed responses

## Sidecar-Specific Headers

The sidecar adds the following headers to responses:

| Header | Description |
|--------|-------------|
| `X-Sidecar-Mode` | Current sidecar mode (shadow, enforce, etc.) |
| `X-Sidecar-Version` | Sidecar version |
| `X-Sidecar-Request-Id` | Unique request identifier for tracing |
| `X-Sidecar-CSS-Comparison` | CSS comparison result (in shadow mode) |
| `X-Sidecar-Decision-Trace` | Authorization decision trace ID |

## Debugging

### Enable Debug Logging

Set the sidecar log level to debug:
```bash
SIDECAR_LOG_LEVEL=debug
```

### Check CSS Comparison Results

In shadow mode, check the comparison results:
```javascript
const response = await fetch(url, { fetch });
const cssComparison = response.headers.get('X-Sidecar-CSS-Comparison');
const nativeDecision = response.headers.get('X-Sidecar-Native-Decision');
const cssDecision = response.headers.get('X-Sidecar-CSS-Decision');

if (cssComparison === 'mismatch') {
  console.warn(`Decision mismatch: native=${nativeDecision}, css=${cssDecision}`);
  // Report this to the sidecar maintainers
}
```

## Performance Considerations

1. **Caching**: The sidecar caches authorization decisions. For development, you may want to disable caching:
   ```bash
   SIDECAR_AUTHZ_CACHE_ENABLED=false
   ```

2. **Rate Limiting**: The sidecar may apply rate limits. For development, you can increase or disable them:
   ```bash
   SIDECAR_RATE_LIMIT_ENABLED=false
   ```

3. **Compression**: The sidecar supports compression. Modern clients handle this automatically.

## Testing Compatibility

To test your client's compatibility with the sidecar:

1. Set up the local development environment (see `../local-dev/`)
2. Configure your client to use the sidecar URL
3. Run through your application's test suite
4. Check for any errors or unexpected behavior
5. Report compatibility issues to the sidecar maintainers

## Additional Resources

- [Solid Protocol Specification](https://solidproject.org/ED/2025/protocol)
- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [WAC Specification](https://solidproject.org/ED/2025/wac)
- [ACP Specification](https://solidproject.org/ED/2025/acp)

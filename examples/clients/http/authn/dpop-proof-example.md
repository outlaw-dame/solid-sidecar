# DPoP Proof Generation Example

**Phase**: 27 - SDK/Client Compatibility Layer  
**Component**: Authentication (DPoP Proof Generation)  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Status**: STABLE - Production Ready  

---

## Overview

This document explains how to generate DPoP (Demonstrating Proof of Possession) proofs for Solid Sidecar authentication. DPoP is specified in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) and is required by Solid-OIDC.

**Key Principle**: Every authenticated request MUST include a DPoP proof JWT that:
1. Is signed with a private key that corresponds to a public key
2. Contains the access token hash (`ath` claim) to bind the proof to the token
3. Specifies the HTTP method (`htm` claim) and URL (`htu` claim)
4. Has a unique identifier (`jti` claim) to prevent replay attacks

---

## DPoP Proof Structure

A DPoP proof is a JWT with the following structure:

```
+-------------------+ +-------------------+ +-------------------+
|  JWT Header       | . |  JWT Claims        | . |  Signature        |
|  (Base64Url)      | . |  (Base64Url)      | . |  (Base64Url)      |
+-------------------+ +-------------------+ +-------------------+
```

### JWT Header

The header MUST contain:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "BASE64URL(X-coordinate)",
    "y": "BASE64URL(Y-coordinate)"
  }
}
```

**Supported algorithms**:
- `ES256` (ECDSA with P-256) - RECOMMENDED
- `ES384` (ECDSA with P-384)
- `ES512` (ECDSA with P-521)
- `RS256` (RSA with SHA-256)
- `RS384` (RSA with SHA-384)
- `RS512` (RSA with SHA-512)
- `EdDSA` (Ed25519)

**Supported key types**:
- `EC` (Elliptic Curve) - RECOMMENDED
- `RSA` (RSA)
- `OKP` (Octet Key Pair) - for EdDSA

### JWT Claims

The claims MUST contain:

```json
{
  "htm": "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  "htu": "https://sidecar.example.com/path",
  "jti": "UNIQUE_NONCE_PER_REQUEST",
  "iat": 1234567890
}
```

And OPTIONALLY:

```json
{
  "ath": "BASE64URL(SHA256(access_token))"  // REQUIRED when access token is present
}
```

**Claim descriptions**:

| Claim | Required | Description | Example |
|-------|----------|-------------|---------|
| `htm` | Yes | HTTP method for the request | `"GET"` |
| `htu` | Yes | HTTP URL for the request (without query params) | `"https://sidecar.example.com/resource"` |
| `jti` | Yes | Unique nonce for this request | `"abc123..."` |
| `iat` | Yes | Issued-at timestamp (Unix epoch) | `1234567890` |
| `ath` | Conditional | Access token hash (SHA-256, base64url) | `"base64url-encoded-hash"` |

---

## Key Generation

### EC P-256 (Recommended)

**OpenSSL**:

```bash
# Generate EC P-256 key pair
openssl ecparam -name prime256v1 -genkey -noout -out dpop-private-key.pem

# Extract public key
openssl ec -in dpop-private-key.pem -pubout -out dpop-public-key.pem

# Extract JWK from public key
openssl ec -in dpop-private-key.pem -pubout -text -noout 2>/dev/null | \
  grep -A5 "pub:" | \
  sed 's/.*: //' | \
  awk '{
    if ($1 == "X:") x=$2
    if ($1 == "Y:") y=$2
    printf "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"}\n", x, y
  }' | \
  jq -c .
```

**Node.js**:

```javascript
const crypto = require('crypto');

// Generate EC P-256 key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'jwk' },
  privateKeyEncoding: { type: 'pkcs8', format: 'jwk' }
});

// publicKey now contains the JWK
console.log(JSON.stringify(publicKey, null, 2));
```

**Python**:

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import json
import base64

# Generate EC P-256 key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Extract public numbers
public_numbers = public_key.public_numbers()

# Create JWK
def to_base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": to_base64url(public_numbers.x.to_bytes(32, 'big')),
    "y": to_base64url(public_numbers.y.to_bytes(32, 'big'))
}

print(json.dumps(jwk, indent=2))
```

---

## DPoP Proof Generation

### Step-by-Step Algorithm

1. **Generate a unique `jti`** (nonce) for this request
2. **Get current timestamp** (`iat`)
3. **Hash the access token** (SHA-256, base64url) for `ath` claim
4. **Create JWT header** with `typ`, `alg`, and `jwk`
5. **Create JWT claims** with `htm`, `htu`, `jti`, `iat`, and `ath`
6. **Base64Url encode header and claims**
7. **Create signing input**: `base64url(header) + "." + base64url(claims)`
8. **Sign signing input** with DPoP private key
9. **Base64Url encode signature**
10. **Concatenate**: `signing_input + "." + base64url(signature)`

### Bash Implementation

```bash
#!/bin/bash

# Inputs (set these before calling)
DPOP_PRIVATE_KEY_PEM="path/to/dpop-private-key.pem"  # PEM-encoded EC private key
ACCESS_TOKEN="your-access-token"                    # Access token to bind
HTTP_METHOD="GET"                                    # HTTP method
HTTP_URL="https://sidecar.example.com/resource"    # HTTP URL (without query params)

# Step 1: Generate unique jti
JTI=$(openssl rand -base64 16 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

# Step 2: Get current timestamp
IAT=$(date +%s)

# Step 3: Hash access token for ath claim
ATH=$(echo -n "$ACCESS_TOKEN" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Step 4-5: Create JWT header and claims
# Note: This assumes you've extracted the JWK from your public key
# For this example, we'll use placeholder JWK values - replace with actual values
JWK='{"kty":"EC","crv":"P-256","x":"BASE64URL_X_COORDINATE","y":"BASE64URL_Y_COORDINATE"}'

HEADER='{"typ":"dpop+jwt","alg":"ES256","jwk":'"$JWK"'}'
CLAIMS='{"htm":"'"$HTTP_METHOD"'","htu":"'"$HTTP_URL"'","jti":"'"$JTI"'","iat":'"$IAT"',"ath":"'"$ATH"'"}'

# Step 6: Base64Url encode header and claims
HEADER_B64U=$(echo -n "$HEADER" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
CLAIMS_B64U=$(echo -n "$CLAIMS" | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Step 7: Create signing input
SIGNING_INPUT="${HEADER_B64U}.${CLAIMS_B64U}"

# Step 8: Sign signing input with private key
SIGNATURE=$(echo -n "$SIGNING_INPUT" | openssl dgst -sha256 -sign "$DPOP_PRIVATE_KEY_PEM" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Step 9-10: Create final DPoP proof
DPOP_PROOF="${SIGNING_INPUT}.${SIGNATURE}"

echo "DPoP Proof: $DPOP_PROOF"
```

### Node.js Implementation

```javascript
const crypto = require('crypto');

async function generateDPoPProof(options) {
  const {
    privateKey,        // JWK or PEM-encoded private key
    accessToken,      // Access token to bind
    method,          // HTTP method (GET, POST, etc.)
    url,             // HTTP URL (without query params)
    jti = crypto.randomBytes(16).toString('base64url'), // Auto-generate if not provided
    issuedAt = Math.floor(Date.now() / 1000)  // Auto-generate if not provided
  } = options;

  // Ensure URL doesn't have query parameters
  const htu = url.split('?')[0];

  // Create JWT header
  // If privateKey is JWK format, use it directly
  // Otherwise, extract JWK from PEM
  let jwk;
  if (typeof privateKey === 'object') {
    jwk = privateKey;
  } else {
    // Convert PEM to JWK (simplified - use a library for production)
    const keyObject = crypto.createPrivateKey(privateKey);
    jwk = keyObject.export({ format: 'jwk' });
  }

  const header = {
    typ: 'dpop+jwt',
    alg: jwk.alg || (jwk.kty === 'EC' ? 'ES256' : 'RS256'),
    jwk: jwk
  };

  // Create JWT claims
  const claims = {
    htm: method.toUpperCase(),
    htu: htu,
    jti: jti,
    iat: issuedAt
  };

  // Add ath claim if access token is provided
  if (accessToken) {
    const ath = crypto
      .createHash('sha256')
      .update(accessToken)
      .digest('base64url');
    claims.ath = ath;
  }

  // Encode header and claims
  const encodeBase64Url = (obj) => {
    return Buffer.from(JSON.stringify(obj))
      .toString('base64url');
  };

  const encodedHeader = encodeBase64Url(header);
  const encodedClaims = encodeBase64Url(claims);

  // Create signing input
  const signingInput = `${encodedHeader}.${encodedClaims}`;

  // Sign with private key
  const keyObject = typeof privateKey === 'object'
    ? crypto.createPrivateKey({ key: privateKey, format: 'jwk' })
    : crypto.createPrivateKey(privateKey);

  const signature = keyObject.sign(
    { input: signingInput, algorithm: header.alg },
    'base64url'
  );

  // Create final DPoP proof
  const dpopProof = `${signingInput}.${signature}`;

  return dpopProof;
}

// Usage example
const privateKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'BASE64URL_X',
  y: 'BASE64URL_Y',
  d: 'BASE64URL_D'  // Private key component
};

generateDPoPProof({
  privateKey: privateKeyJwk,
  accessToken: 'your-access-token',
  method: 'GET',
  url: 'https://sidecar.example.com/resource'
}).then(dpopProof => {
  console.log('DPoP Proof:', dpopProof);
});
```

### Python Implementation

```python
import json
import time
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization


def base64url_encode(data):
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def generate_dpop_proof(options):
    """
    Generate a DPoP proof JWT.
    
    Args:
        private_key: PEM-encoded private key or key object
        access_token: Access token to bind (optional)
        method: HTTP method (GET, POST, etc.)
        url: HTTP URL (without query params)
        jti: Unique nonce (auto-generated if not provided)
        iat: Issued-at timestamp (auto-generated if not provided)
    
    Returns:
        str: DPoP proof JWT
    """
    # Load private key if PEM-encoded
    if isinstance(private_key, str):
        private_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None
        )
    
    # Generate jti if not provided
    jti = options.get('jti') or base64url_encode(
        hashlib.sha256(str(time.time()).encode()).digest()
    )
    
    # Get current timestamp if not provided
    iat = options.get('iat') or int(time.time())
    
    # Remove query params from URL
    htu = options['url'].split('?')[0]
    
    # Create JWT header
    # Extract JWK from public key
    public_key = private_key.public_key()
    
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        jwk = {
            "kty": "EC",
            "crv": "P-256" if isinstance(public_key.curve, ec.SECP256R1) else "P-384",
            "x": base64url_encode(public_key.public_numbers().x.to_bytes(32, 'big')),
            "y": base64url_encode(public_key.public_numbers().y.to_bytes(32, 'big'))
        }
        alg = "ES256" if isinstance(public_key.curve, ec.SECP256R1) else "ES384"
    else:
        raise ValueError("Unsupported key type")
    
    header = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": jwk
    }
    
    # Create JWT claims
    claims = {
        "htm": options['method'].upper(),
        "htu": htu,
        "jti": jti,
        "iat": iat
    }
    
    # Add ath claim if access token is provided
    if options.get('access_token'):
        ath = base64url_encode(
            hashlib.sha256(options['access_token'].encode()).digest()
        )
        claims["ath"] = ath
    
    # Encode header and claims
    encoded_header = base64url_encode(json.dumps(header).encode())
    encoded_claims = base64url_encode(json.dumps(claims).encode())
    
    # Create signing input
    signing_input = f"{encoded_header}.{encoded_claims}"
    
    # Sign with private key
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(
            signing_input.encode(),
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
    else:
        raise ValueError("Unsupported key type")
    
    encoded_signature = base64url_encode(signature)
    
    # Create final DPoP proof
    dpop_proof = f"{signing_input}.{encoded_signature}"
    
    return dpop_proof


# Usage example
private_key_pem = """-----BEGIN EC PRIVATE KEY-----
... your private key ...
-----END EC PRIVATE KEY-----"""

dpop_proof = generate_dpop_proof({
    'private_key': private_key_pem,
    'access_token': 'your-access-token',
    'method': 'GET',
    'url': 'https://sidecar.example.com/resource'
})

print(f"DPoP Proof: {dpop_proof}")
```

---

## Using DPoP Proof with HTTP Requests

Once you have generated a DPoP proof, include it in your HTTP request headers:

### cURL Example

```bash
#!/bin/bash

# Set your tokens and proof
ACCESS_TOKEN="your-access-token"
DPOP_PROOF="your-dpop-proof-jwt"
RESOURCE_URL="https://sidecar.example.com/resource"

# Make authenticated request
curl -i \
  -X GET "$RESOURCE_URL" \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF"
```

**Important**: The `DPoP` header contains ONLY the DPoP proof JWT (not the access token).

### Node.js (fetch) Example

```javascript
const fetch = require('node-fetch');

async function fetchWithDPoP(url, options = {}) {
  const { dpopProof, accessToken, ...fetchOptions } = options;
  
  const headers = {
    ...fetchOptions.headers,
    'Authorization': `DPoP ${accessToken}`,
    'DPoP': dpopProof
  };
  
  return fetch(url, {
    ...fetchOptions,
    headers
  });
}

// Usage
fetchWithDPoP('https://sidecar.example.com/resource', {
  accessToken: 'your-access-token',
  dpopProof: await generateDPoPProof({ ... })
}).then(response => response.json());
```

### Python (requests) Example

```python
import requests

def request_with_dpop(method, url, access_token, dpop_proof, **kwargs):
    headers = {
        **kwargs.get('headers', {}),
        'Authorization': f'DPoP {access_token}',
        'DPoP': dpop_proof
    }
    
    return requests.request(
        method.upper(),
        url,
        headers=headers,
        **kwargs
    )

# Usage
response = request_with_dpop(
    'GET',
    'https://sidecar.example.com/resource',
    access_token='your-access-token',
    dpop_proof=generate_dpop_proof({ ... })
)
print(response.json())
```

---

## Security Best Practices

### Key Storage

1. **Never store private keys in plaintext**
   - Use platform secure storage (Keychain on iOS/macOS, Keystore on Android, TPM on Linux)
   - If you must store on disk, encrypt with a strong passphrase

2. **Use hardware-backed keys when available**
   - iOS: Secure Enclave
   - Android: AndroidKeyStore with StrongBox if available
   - Linux: TPM
   - macOS: Secure Enclave

3. **Rotate DPoP keys periodically**
   - Generate new key pairs regularly (e.g., weekly)
   - When rotating, obtain new tokens with the new key

### DPoP Proof Generation

1. **Always use unique `jti` for each request**
   - Prevents replay attacks
   - Track recently used `jti` values to prevent reuse

2. **Always bind to access token with `ath` claim**
   - Prevents token substitution attacks
   - The `ath` claim MUST be the SHA-256 hash of the access token

3. **Validate all inputs**
   - Validate HTTP method and URL before generating proof
   - Ensure URL doesn't contain sensitive information

4. **Use short-lived proofs**
   - Set reasonable expiration (though DPoP proofs are typically used immediately)
   - The server validates `iat` to prevent old proofs

### Request Signing

1. **Generate DPoP proof immediately before sending**
   - Don't cache DPoP proofs
   - Each request gets its own unique proof

2. **Match `htm` and `htu` exactly to the request**
   - `htm` must match the HTTP method (case-sensitive)
   - `htu` must match the request URL (without query parameters)

3. **Never expose DPoP proofs in logs**
   - Treat DPoP proofs as sensitive credentials
   - Redact from logs and error messages

---

## Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `DPoP proof missing` | No DPoP header | Include DPoP header with proof JWT |
| `DPoP proof signature invalid` | Wrong private key or algorithm | Use correct private key and algorithm |
| `DPoP htm does not match request method` | Method mismatch | Ensure `htm` matches actual HTTP method |
| `DPoP htu does not match request target` | URL mismatch | Ensure `htu` matches request URL (without query) |
| `DPoP ath does not match access token` | Token binding mismatch | Hash the access token correctly for `ath` |
| `DPoP proof is too old` | Proof timestamp too old | Generate fresh proof with current timestamp |
| `DPoP jti is required` | Missing nonce | Generate unique `jti` for each proof |
| `DPoP proof replay` | Reusing a `jti` | Generate unique `jti` for each request |

---

## Testing

Test your DPoP implementation with:

1. **Valid DPoP proof with correct binding**
   - Should succeed

2. **DPoP proof with wrong `htm`**
   - Should fail with method mismatch

3. **DPoP proof with wrong `htu`**
   - Should fail with URL mismatch

4. **DPoP proof with wrong `ath`**
   - Should fail with token binding mismatch

5. **Reused DPoP proof (same `jti`)**
   - Should fail with replay detection

6. **DPoP proof signed with wrong key**
   - Should fail with signature invalid

---

## References

- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [Solid-OIDC Specification](https://solid.github.io/solid-oidc/)
- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [Client Contract](../docs/client-contract.md)
- [Client Security Requirements](../docs/client-security.md)

# Authentication Examples

**Phase**: 27 - SDK/Client Compatibility Layer  
**Component**: Authentication (DPoP + Solid-OIDC)  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Status**: STABLE - Production Ready  

---

## Overview

This directory contains authentication examples for Solid Sidecar. Solid Sidecar implements **DPoP-bound access tokens** as specified by [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) and the [Solid-OIDC specification](https://solid.github.io/solid-oidc/).

**Key Principle**: Every authenticated request to Solid Sidecar MUST include:
1. A valid access token in the `Authorization` header
2. A DPoP proof JWT in the `DPoP` header
3. Both must be cryptographically bound together

---

## Authentication Flow

```
+------------------+       +------------------+       +------------------+
|   OIDC Issuer   |       |   Your Client    |       |   Solid Sidecar  |
|  (e.g., Inrupt)  |       |  (this example)  |       | + CSS Backend    |
+------------------+       +------------------+       +------------------+
         |                          |                          |
         | 1. PKCE Authorization      |                          |
         |    Request                 |                          |
         +-------------------------->|                          |
         |                          |                          |
         | 2. Authorization Code      |                          |
         |    (user redirects)        |                          |
         +-------------------------->|                          |
         |                          |                          |
         | 3. Token Request           |                          |
         |    (with PKCE code_verifier)|                          |
         +-------------------------->|                          |
         | 4. Access Token + Refresh  |                          |
         |    Token Response          |                          |
         +---------------------------->|                          |
         |                          |                          |
         |                          | 5. Generate DPoP Key Pair |
         |                          |    (on client device)     |
         |                          +-------------------------->|
         |                          |                          |
         |                          | 6. Generate DPoP Proof   |
         |                          |    (signed with private key)|
         |                          +-------------------------->|
         |                          |                          |
         |                          | 7. API Request with:     |
         |                          |    - Authorization: Bearer |
         |                          |    - DPoP: proof JWT      |
         |                          +-------------------------->|
         |                          |                          |
         |                          | 8. Verify:               |
         |                          |    - Access token signature|
         |                          |    - DPoP proof signature |
         |                          |    - ath = hash(token)    |
         |                          |    - htm = HTTP method    |
         |                          |    - htu = HTTP URI       |
         |                          |    - jti uniqueness       |
         |                          |    - Replay prevention    |
         +--------------------------+--------------------------+
```

---

## DPoP Proof Requirements

A valid DPoP proof JWT MUST contain:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256" | "RS256" | "EdDSA",
  "jwk": {
    "kty": "EC" | "RSA" | "OKP",
    "crv": "P-256" | "P-384" | "P-521" | "Ed25519",
    "x": "base64url-encoded-x-coordinate",
    "y": "base64url-encoded-y-coordinate"
  }
}
```

With claims:

```json
{
  "htm": "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  "htu": "https://sidecar.example.com/resource",
  "jti": "unique-nonce-per-request",
  "iat": 1234567890,
  "ath": "base64url(sha256(access_token))"
}
```

---

## Files in This Directory

| File | Description | Language |
|------|-------------|----------|
| [dpop-proof-example.md](./dpop-proof-example.md) | Detailed DPoP proof generation explanation | Markdown |
| [token-exchange.sh](./token-exchange.sh) | PKCE token exchange flow | Bash + curl |
| [refresh-token.sh](./refresh-token.sh) | Refresh access token with DPoP | Bash + curl |
| [dpop-sign-request.sh](./dpop-sign-request.sh) | Sign HTTP request with DPoP | Bash + curl + OpenSSL |

---

## Token Exchange (PKCE)

The token exchange flow uses **Proof Key for Code Exchange (PKCE)** to prevent authorization code interception attacks.

### Steps:

1. Generate a `code_verifier` (43-128 char random string)
2. Generate a `code_challenge` = base64url(sha256(code_verifier))
3. Redirect user to OIDC issuer with `code_challenge`
4. User authenticates and is redirected back with `code`
5. Exchange `code` + `code_verifier` for tokens

### Example:

```bash
# Generate code_verifier (64 bytes random)
CODE_VERIFIER=$(openssl rand -base64 48 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

# Generate code_challenge
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Start authorization flow
AUTH_URL="$OIDC_ISSUER/auth?"\
  "response_type=code"\
  "&client_id=$CLIENT_ID"\
  "&redirect_uri=$REDIRECT_URI"\
  "&code_challenge=$CODE_CHALLENGE"\
  "&code_challenge_method=S256"\
  "&scope=openid%20profile%20webid"\
  "&state=random-state"\
  "&nonce=random-nonce"

# User visits AUTH_URL, authenticates, gets redirected to REDIRECT_URI?code=AUTH_CODE

# Exchange code for tokens
curl -X POST "$OIDC_ISSUER/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$CODE_VERIFIER"
```

---

## DPoP Key Generation

The DPoP key pair MUST be generated on the client device and stored securely.

### iOS (Swift):

```swift
import CryptoKit

let accessControl = SecAccessControlCreateWithFlags(
    nil,
    .privateKeyUsage,
    .devicePasscode,
    nil
)

let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrAccessControl as String: accessControl
    ]
]

var error: Unmanaged<CFError>?
let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
```

### Android (Kotlin):

```kotlin
val keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC,
    "AndroidKeyStore"
)

val keyGenParameterSpec = KeyGenParameterSpec.Builder(
    "dpop-key",
    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
).apply {
    setDigests(Digest.SHA256)
    setSignaturePaddings(Signature.UNDEFINED)
    setUserAuthenticationRequired(false)
    setRandomizedEncryptionRequired(false)
}.build()

keyPairGenerator.initialize(keyGenParameterSpec)
val keyPair = keyPairGenerator.generateKeyPair()
```

### Node.js:

```javascript
const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'jwk' },
  privateKeyEncoding: { type: 'pkcs8', format: 'jwk' }
});
```

### Python:

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Export as JWK
public_jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": base64urlencode(private_key.public_key().public_numbers().x).decode(),
    "y": base64urlencode(private_key.public_key().public_numbers().y).decode()
}
```

---

## DPoP Proof Generation

The DPoP proof MUST be generated for each request with a unique `jti`.

### Algorithm:

1. Generate a unique `jti` (nonce) for this request
2. Create the JWT header with `typ: dpop+jwt` and public key in `jwk`
3. Create the JWT claims with `htm`, `htu`, `jti`, `iat`, and `ath`
4. Sign the JWT with the DPoP private key

### Example (using OpenSSL):

```bash
# Assumes:
# - DPOP_PRIVATE_KEY_PEM: Path to PEM-encoded EC private key
# - ACCESS_TOKEN: The access token
# - HTTP_METHOD: GET, POST, etc.
# - HTTP_URL: The full URL (without query parameters?)
# - JTI: Unique nonce for this request
# - IAT: Current timestamp

# Create JWT header
HEADER='{"typ":"dpop+jwt","alg":"ES256","jwk":{'\n  \"kty\":\"EC\",'\n  \"crv\":\"P-256\",'\n  \"x\":\"BASE64URL_X\",'\n  \"y\":\"BASE64URL_Y\"'\n}}'

# Create JWT claims
CLAIMS='{"htm":"'"$HTTP_METHOD"'","htu":"'"$HTTP_URL"'","jti":"'"$JTI"'","iat":'"$IAT"',"ath":"'"$(echo -n "$ACCESS_TOKEN" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')'""}'

# Create signing input
SIGNING_INPUT=$(echo -n "$HEADER" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
SIGNING_INPUT+="."$(echo -n "$CLAIMS" | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Sign with private key
SIGNATURE=$(echo -n "$SIGNING_INPUT" | openssl dgst -sha256 -sign "$DPOP_PRIVATE_KEY_PEM" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Final DPoP proof
DPOP_PROOF="$SIGNING_INPUT.$SIGNATURE"
```

---

## Security Requirements

All authentication implementations MUST:

1. **Use HTTPS**: Never send tokens or DPoP proofs over HTTP
2. **Validate All Inputs**: Validate OIDC issuer, client_id, redirect_uri, scopes
3. **Generate Strong Nonces**: Use cryptographically secure random for code_verifier, jti, state, nonce
4. **Store Keys Securely**: Use platform key storage (Keychain, Keystore, TPM, Secure Enclave)
5. **Rotate Keys**: Generate new DPoP key pairs periodically
6. **Prevent Replay**: Use unique jti for each request, track recently used jti values
7. **Bind Tokens**: Always include ath claim in DPoP proof
8. **Verify SSL**: Validate certificate chains, use certificate pinning for production
9. **Handle Errors**: Don't expose sensitive information in error messages
10. **Log Security Events**: Log authentication attempts (without sensitive data)

---

## Error Handling

| Error | Retryable | Action |
|-------|-----------|--------|
| Invalid Grant | No | Fail with authentication error |
| Invalid Token | No | Refresh token or fail |
| Token Expired | No | Refresh token |
| DPoP Proof Invalid | No | Generate new proof |
| DPoP Proof Reused | No | Generate new proof with new jti |
| Rate Limited (429) | Yes | Wait and retry with backoff |
| Server Error (5xx) | Yes | Retry with exponential backoff |
| Network Error | Yes | Retry with exponential backoff |

---

## Testing

Test your authentication implementation with:

1. Valid credentials and valid DPoP proof
2. Valid credentials but missing DPoP proof
3. Valid credentials but invalid DPoP proof (wrong key)
4. Valid credentials but reused DPoP proof
5. Invalid access token
6. Expired access token (with refresh)
7. Network interruptions during token exchange
8. Network interruptions during API requests

---

## References

- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [Solid-OIDC Specification](https://solid.github.io/solid-oidc/)
- [Solid Protocol Specification](https://solidproject.org/TR/protocol)
- [Client Contract](../docs/client-contract.md)
- [Client Security Requirements](../docs/client-security.md)

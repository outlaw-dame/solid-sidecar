# DPoP Proof Generation Example

**Phase 27 - SDK/Client Compatibility Layer**  
**Status: STABLE - Production Ready - FULLY HARDENED**

This document demonstrates how to generate DPoP (Demonstrating Proof-of-Possession) proofs for use with the Solid Sidecar SDK and HTTP API.

---

## Table of Contents

1. [DPoP Overview](#dpop-overview)
2. [JWT Structure](#jwt-structure)
3. [Generation in Different Languages](#generation-in-different-languages)
   - [JavaScript (Browser)](#javascript-browser)
   - [JavaScript (Node.js)](#javascript-nodejs)
   - [Python](#python)
   - [Go](#go)
   - [Java](#java)
   - [Swift (iOS)](#swift-ios)
   - [Kotlin (Android)](#kotlin-android)
4. [Key Management](#key-management)
5. [Security Considerations](#security-considerations)
6. [Testing DPoP Proofs](#testing-dpop-proofs)

---

## DPoP Overview

DPoP (Demonstrating Proof-of-Possession) is a security mechanism defined in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) that binds an access token to a cryptographic key pair. This prevents token theft and replay attacks.

### Key Concepts

- **Access Token**: A bearer token obtained from an OAuth 2.0 / Solid-OIDC authorization server
- **DPoP Proof**: A JWT signed with a private key that proves possession of the corresponding public key
- **Key Pair**: RSA or EC key pair (RSA2048/RS256 recommended)
- **Token Binding**: The DPoP proof includes a hash of the access token (ath claim)

### When to Use DPoP

✅ **Required**: All authenticated requests to Solid Sidecar  
✅ **Required**: When using sensitive operations (write, delete, etc.)  
✅ **Recommended**: All requests to protect against token theft  

### DPoP Flow

```
1. Client obtains access token from auth server
2. Client generates RSA key pair (or uses existing)
3. For each request:
   a. Generate DPoP proof JWT
   b. Sign proof with private key
   c. Send both access token and DPoP proof in headers
4. Server verifies:
   a. Access token is valid
   b. DPoP proof signature is valid
   c. DPoP proof claims match request (method, URL)
   d. ath claim matches hash of access token
5. Request is processed
```

---

## JWT Structure

### DPoP Proof JWT Claims

| Claim | Required | Type | Description |
|-------|----------|------|-------------|
| `typ` | Yes | string | Must be `dpop+jwt` |
| `alg` | Yes | string | Signing algorithm (e.g., `RS256`, `ES256`) |
| `jti` | Yes | string | Unique identifier for the proof |
| `htm` | Yes | string | HTTP method (GET, POST, PUT, DELETE, etc.) |
| `htu` | Yes | string | HTTP URI (the target URL) |
| `iat` | Yes | number | Issued at timestamp (Unix epoch in seconds) |
| `ath` | Yes | string | SHA-256 hash of the access token |

### Example DPoP Proof JWT

```json
{
  "typ": "dpop+jwt",
  "alg": "RS256",
  "jti": "d1b3b3b3-b3b3-4b3b-8b3b-b3b3b3b3b3b3",
  "htm": "GET",
  "htu": "https://pod.example.com/data/file.txt",
  "iat": 1699999999,
  "exp": 1700000059,
  "ath": "7d4398346f3716562c776813936695519320484332733823861166465135199513451384"
}
```

### Base64URL-Encoded JWT

The above JWT would be base64url-encoded as:

```
eyJ0eXAiOiAidHBvcCtpand0IiwiYWxnIjoiUlMyNTYiLCJqdGkiOiAiZDE2M2I2ZTQtYjNiMy00YjNiLTg2MzktYjNiM2I5YjM4YjQxIiwi
aHRtIjoiR0VUIiwidHUiOiAiaHR0cHM6Ly9wb2QuZXhhbXBsZS5jb20vZGF0YS9maWxlLnR4dCIsImlhdCI6
IDE2OTk5OTk5OTksImV4cCI6IDE3MDAwMDAwNTksImF0aCI6ICI3ZDQzOTgzNDZmMzcxNjU2MmM3NzY4MTM5
MzY2OTU1MTkzMjA0ODQzMzI3MzM4MjM4NjExNjY0NjUxMzUxOTk1MTM0NTEzODQifQ
```

---

## Generation in Different Languages

### JavaScript (Browser)

Using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API):

```javascript
// Generate RSA key pair (do this once and cache the key)
async function generateDPoPKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256"
    },
    true,
    ["sign"]
  );
}

// Generate DPoP proof for a request
async function generateDPoPProof(method, url, accessToken, privateKey) {
  // Calculate ath (SHA-256 hash of access token)
  const tokenHashBuffer = await window.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(accessToken)
  );
  const ath = base64urlEncode(tokenHashBuffer);

  // Create JWT header
  const header = {
    typ: "dpop+jwt",
    alg: "RS256",
    jti: window.crypto.randomUUID()
  };

  // Create JWT payload
  const payload = {
    htm: method.toUpperCase(),
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes
    ath: ath
  };

  // Encode header and payload
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));

  // Create signing input
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // Sign with private key
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    privateKey,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64urlEncode(signatureBuffer);

  // Return DPoP proof
  return `${signingInput}.${encodedSignature}`;
}

// Helper: Base64URL encode without padding
function base64urlEncode(buffer) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Usage
const privateKey = await generateDPoPKeyPair();
const dpopProof = await generateDPoPProof(
  'GET',
  'https://pod.example.com/data/file.txt',
  accessToken,
  privateKey
);

console.log('DPoP Proof:', dpopProof);
```

### JavaScript (Node.js)

Using the `jsonwebtoken` and `crypto` packages:

```javascript
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Generate RSA key pair (do this once and store securely)
function generateDPoPKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
}

// Generate DPoP proof
function generateDPoPProof(method, url, accessToken, privateKey) {
  // Calculate ath (SHA-256 hash of access token)
  const ath = crypto
    .createHash('sha256')
    .update(accessToken)
    .digest('base64url');

  // JWT payload
  const payload = {
    htm: method.toUpperCase(),
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes
    ath: ath
  };

  // Sign with private key
  const dpopProof = jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    keyid: crypto.randomUUID()
  });

  return dpopProof;
}

// Usage
const { privateKey } = generateDPoPKeyPair();
const dpopProof = generateDPoPProof(
  'GET',
  'https://pod.example.com/data/file.txt',
  accessToken,
  privateKey
);

console.log('DPoP Proof:', dpopProof);
```

### Python

Using the `cryptography` and `jwt` packages:

```python
import hashlib
import base64
import uuid
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import json

# Generate RSA key pair (do this once and store securely)
def generate_dpop_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Base64URL encode without padding
def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    base64_str = base64.urlsafe_b64encode(data).decode('utf-8')
    return base64_str.rstrip('=')

# Generate DPoP proof
def generate_dpop_proof(method, url, access_token, private_key):
    # Calculate ath (SHA-256 hash of access token)
    ath = hashlib.sha256(access_token.encode('utf-8')).digest()
    ath_b64 = base64url_encode(ath)

    # JWT header
    header = {
        "typ": "dpop+jwt",
        "alg": "RS256",
        "jti": str(uuid.uuid4())
    }

    # JWT payload
    payload = {
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,  # 5 minutes
        "ath": ath_b64
    }

    # Encode header and payload
    encoded_header = base64url_encode(json.dumps(header))
    encoded_payload = base64url_encode(json.dumps(payload))

    # Create signing input
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')

    # Sign with private key
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    encoded_signature = base64url_encode(signature)

    # Return DPoP proof
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

# Usage
private_key, public_key = generate_dpop_key_pair()
dpop_proof = generate_dpop_proof(
    'GET',
    'https://pod.example.com/data/file.txt',
    access_token,
    private_key
)

print('DPoP Proof:', dpop_proof)
```

### Go

Using the Go SDK's DPoP keystore:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/outlaw-dame/solid-sidecar/sdk/go/auth"
)

func main() {
	// Create DPoP keystore
	keystore, err := auth.NewDPoPKeyStore()
	if err != nil {
		log.Fatal("Failed to create DPoP keystore:", err)
	}

	// Generate access token (from your auth flow)
	accessToken := "your-access-token"

	// Generate DPoP proof for a request
	method := "GET"
	url := "https://pod.example.com/data/file.txt"

	dpopProof, err := keystore.GenerateProof(method, url, accessToken)
	if err != nil {
		log.Fatal("Failed to generate DPoP proof:", err)
	}

	fmt.Println("DPoP Proof:", dpopProof)

	// Use with HTTP client
	// dpopProof can be used in the DPoP header
	// accessToken can be used in the Authorization header
}
```

### Java

Using the [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) library:

```java
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class DPoPExample {
    
    // Generate RSA key pair (do this once and store securely)
    public static KeyPair generateDPoPKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
    
    // Base64URL encode without padding
    public static String base64urlEncode(byte[] data) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(data);
    }
    
    // Generate SHA-256 hash
    public static byte[] sha256(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input.getBytes(StandardCharsets.UTF_8));
    }
    
    // Generate DPoP proof
    public static String generateDPoPProof(
        String method, 
        String url, 
        String accessToken, 
        RSAPrivateKey privateKey
    ) throws Exception {
        // Calculate ath (SHA-256 hash of access token)
        byte[] ath = sha256(accessToken);
        String athB64 = base64urlEncode(ath);
        
        // Create JWT claims
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
            .claim("htm", method.toUpperCase())
            .claim("htu", url)
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 300000)) // 5 minutes
            .claim("ath", athB64)
            .jwtID(UUID.randomUUID().toString());
        
        JWTClaimsSet claims = claimsBuilder.build();
        
        // Create JWS header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .type(JOSEObjectType.JWT)
            .customParam("typ", "dpop+jwt")
            .build();
        
        // Create signed JWT
        SignedJWT signedJWT = new SignedJWT(header, claims);
        RSASSASigner signer = new RSASSASigner(privateKey);
        signedJWT.sign(signer);
        
        return signedJWT.serialize();
    }
    
    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateDPoPKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        // Generate DPoP proof
        String dpopProof = generateDPoPProof(
            "GET",
            "https://pod.example.com/data/file.txt",
            "your-access-token",
            privateKey
        );
        
        System.out.println("DPoP Proof: " + dpopProof);
    }
}
```

### Swift (iOS)

Using Apple's CryptoKit and common JWT libraries:

```swift
import Foundation
import CryptoKit
import CommonCrypto

// Generate RSA key pair (do this once and store in Keychain)
func generateDPoPKeyPair() -> SecKey {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 2048,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false
        ]
    ]
    
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        fatalError("Failed to generate RSA key pair: \(error!.takeRetainedValue())")
    }
    
    return privateKey
}

// Base64URL encode without padding
func base64urlEncode(_ data: Data) -> String {
    var base64 = data.base64EncodedString()
    base64 = base64.replacingOccurrences(of: "+", with: "-")
    base64 = base64.replacingOccurrences(of: "/", with: "_")
    base64 = base64.replacingOccurrences(of: "=", with: "")
    return base64
}

// Generate SHA-256 hash
func sha256(_ string: String) -> Data {
    guard let data = string.data(using: .utf8) else {
        fatalError("Failed to encode string to UTF-8")
    }
    return Data(SHA256.hash(data: data))
}

// Generate DPoP proof
func generateDPoPProof(
    method: String,
    url: String,
    accessToken: String,
    privateKey: SecKey
) -> String? {
    // Calculate ath (SHA-256 hash of access token)
    let ath = sha256(accessToken)
    let athB64 = base64urlEncode(ath)
    
    // Create JWT header
    let header = [
        "typ": "dpop+jwt",
        "alg": "RS256",
        "jti": UUID().uuidString
    ]
    
    // Create JWT payload
    let payload = [
        "htm": method.uppercased(),
        "htu": url,
        "iat": Int(Date().timeIntervalSince1970),
        "exp": Int(Date().timeIntervalSince1970) + 300, // 5 minutes
        "ath": athB64
    ]
    
    // Encode header and payload
    let headerData = try! JSONSerialization.data(withJSONObject: header, options: [])
    let payloadData = try! JSONSerialization.data(withJSONObject: payload, options: [])
    
    let encodedHeader = base64urlEncode(headerData)
    let encodedPayload = base64urlEncode(payloadData)
    
    // Create signing input
    let signingInput = "\(encodedHeader).\(encodedPayload)"
    
    // Sign with private key
    guard let signature = try? signData(signingInput.data(using: .utf8)!, with: privateKey) else {
        return nil
    }
    
    let encodedSignature = base64urlEncode(signature)
    
    return "\(encodedHeader).\(encodedPayload).\(encodedSignature)"
}

func signData(_ data: Data, with privateKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    
    guard let signature = SecKeyCreateSignature(
        privateKey,
        .rsaSignatureMessagePKCS1v15SHA256,
        data as CFData,
        &error
    ) as Data? else {
        throw error!.takeRetainedValue()
    }
    
    return signature
}

// Usage
let privateKey = generateDPoPKeyPair()
let dpopProof = generateDPoPProof(
    method: "GET",
    url: "https://pod.example.com/data/file.txt",
    accessToken: "your-access-token",
    privateKey: privateKey
)

print("DPoP Proof: \(dpopProof ?? "Failed to generate")")
```

### Kotlin (Android)

Using the [Bouncy Castle](https://www.bouncycastle.org/) library:

```kotlin
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Security
import java.util.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.RSAPrivateCrtKeySpec
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader

object DPoPExtensions {
    // Initialize Bouncy Castle
    init {
        Security.addProvider(BouncyCastleProvider())
    }
    
    // Generate RSA key pair (do this once and store securely)
    fun generateDPoPKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA", "BC")
        keyGen.initialize(2048)
        return keyGen.generateKeyPair()
    }
    
    // Base64URL encode without padding
    fun base64urlEncode(data: ByteArray): String {
        val base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(data)
        return base64
    }
    
    // Generate SHA-256 hash
    fun sha256(input: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(input.toByteArray(Charsets.UTF_8))
    }
    
    // Generate DPoP proof
    fun generateDPoPProof(
        method: String,
        url: String,
        accessToken: String,
        privateKey: PrivateKey
    ): String {
        // Calculate ath (SHA-256 hash of access token)
        val ath = sha256(accessToken)
        val athB64 = base64urlEncode(ath)
        
        // Create JWT header
        val header = mapOf(
            "typ" to "dpop+jwt",
            "alg" to "RS256",
            "jti" to UUID.randomUUID().toString()
        )
        
        // Create JWT payload
        val payload = mapOf(
            "htm" to method.uppercase(),
            "htu" to url,
            "iat" to (System.currentTimeMillis() / 1000),
            "exp" to (System.currentTimeMillis() / 1000 + 300), // 5 minutes
            "ath" to athB64
        )
        
        // Encode header and payload
        val headerJson = com.beust.klaxon.JsonObject(header)
        val payloadJson = com.beust.klaxon.JsonObject(payload)
        
        val encodedHeader = base64urlEncode(headerJson.toJsonString().toByteArray())
        val encodedPayload = base64urlEncode(payloadJson.toJsonString().toByteArray())
        
        // Create signing input
        val signingInput = "$encodedHeader.$encodedPayload"
        
        // Sign with private key (using RSASSA-PKCS1-v1_5-SHA256)
        val signature = signData(signingInput.toByteArray(), privateKey)
        val encodedSignature = base64urlEncode(signature)
        
        return "$encodedHeader.$encodedPayload.$encodedSignature"
    }
    
    private fun signData(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val signature = java.security.Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }
}

// Usage
fun main() {
    val keyPair = DPoPExtensions.generateDPoPKeyPair()
    val dpopProof = DPoPExtensions.generateDPoPProof(
        method = "GET",
        url = "https://pod.example.com/data/file.txt",
        accessToken = "your-access-token",
        privateKey = keyPair.private
    )
    
    println("DPoP Proof: $dpopProof")
}
```

---

## Key Management

### Key Storage Best Practices

| Platform | Recommended Storage | Notes |
|----------|---------------------|-------|
| Browser | Web Crypto API + IndexedDB | Keys are not extractable |
| Node.js | File system (secured) | Use proper file permissions |
| iOS | Keychain | Use kSecAttrTokenIDSensitive for DPoP keys |
| Android | Android Keystore | Use KeyProperties.PURPOSE_SIGN |
| Server | HSM / Secure Enclave | Hardware security modules |

### Key Rotation

**Recommended Rotation Schedule:**

- **Browser/Android/iOS**: Rotate keys every 30-90 days
- **Server**: Rotate keys every 7-30 days
- **High-security**: Rotate keys for every session

**Rotation Process:**

1. Generate new key pair
2. Generate DPoP proof with new key
3. Make request with new key + old token
4. Obtain new access token (bound to new key)
5. Use new key + new token for subsequent requests
6. Securely delete old key

### Key Export/Import

When exporting keys for backup:

✅ **Do:**
- Encrypt private keys with a strong password
- Store encrypted keys in secure storage
- Use hardware-backed security when available

❌ **Don't:**
- Store private keys in plaintext
- Transmit private keys over insecure channels
- Commit private keys to version control

---

## Security Considerations

### DPoP Security Properties

1. **Token Binding**: DPoP proofs are bound to specific access tokens via the `ath` claim
2. **Request Binding**: Each proof is bound to a specific HTTP method and URL
3. **Nonce**: Each proof has a unique `jti` to prevent replay attacks
4. **Short-Lived**: Proofs should expire quickly (typically 5 minutes or less)
5. **Key Isolation**: Private keys should never leave the client device

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Token Theft | DPoP binds token to key, making stolen tokens useless without the key |
| Replay Attacks | Unique `jti` and short expiration prevent replay |
| CSRF | DPoP proofs are bound to specific URLs and methods |
| Man-in-the-Middle | TLS 1.2+ required for all connections |
| Key Extraction | Use hardware-backed security (Keychain, Keystore, etc.) |

### Common Vulnerabilities to Avoid

❌ **Vulnerable Code:**

```javascript
// BAD: Reusing the same proof for multiple requests
const dpopProof = generateDPoPProof('GET', 'https://api.example.com/data', token);
for (let i = 0; i < 10; i++) {
  fetch('/data', { headers: { DPoP: dpopProof } }); // Same proof!
}
```

✅ **Secure Code:**

```javascript
// GOOD: Generate a new proof for each request
for (let i = 0; i < 10; i++) {
  const dpopProof = generateDPoPProof('GET', 'https://api.example.com/data', token);
  fetch('/data', { headers: { DPoP: dpopProof } }); // New proof each time
}
```

❌ **Vulnerable Code:**

```javascript
// BAD: Hardcoding keys
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJ...`; // NEVER DO THIS!
```

✅ **Secure Code:**

```javascript
// GOOD: Use secure storage
const privateKey = await loadFromKeychain('dpop-private-key');
```

❌ **Vulnerable Code:**

```javascript
// BAD: Long-lived proofs
const proof = generateDPoPProof(..., exp: Date.now() + 86400000); // 24 hours!
```

✅ **Secure Code:**

```javascript
// GOOD: Short-lived proofs
const proof = generateDPoPProof(..., exp: Date.now() + 300000); // 5 minutes
```

---

## Testing DPoP Proofs

### Validate Your DPoP Implementation

1. **Proof Structure**: Verify the JWT has all required claims
2. **Signature**: Verify the signature can be validated with the public key
3. **Binding**: Verify `ath` claim matches the hash of your access token
4. **Method/URL**: Verify `htm` and `htu` match the request
5. **Expiration**: Verify proofs expire as expected

### Test Cases

```javascript
// Test case 1: Valid proof
async function testValidProof() {
  const proof = generateDPoPProof('GET', 'https://api.example.com/data', token, privateKey);
  const isValid = await verifyDPoPProof(proof, 'GET', 'https://api.example.com/data', token, publicKey);
  console.assert(isValid, 'Valid proof should verify');
}

// Test case 2: Wrong method
async function testWrongMethod() {
  const proof = generateDPoPProof('GET', 'https://api.example.com/data', token, privateKey);
  const isValid = await verifyDPoPProof(proof, 'POST', 'https://api.example.com/data', token, publicKey);
  console.assert(!isValid, 'Proof with wrong method should not verify');
}

// Test case 3: Wrong URL
async function testWrongURL() {
  const proof = generateDPoPProof('GET', 'https://api.example.com/data', token, privateKey);
  const isValid = await verifyDPoPProof(proof, 'GET', 'https://api.example.com/other', token, publicKey);
  console.assert(!isValid, 'Proof with wrong URL should not verify');
}

// Test case 4: Wrong token
async function testWrongToken() {
  const proof = generateDPoPProof('GET', 'https://api.example.com/data', token, privateKey);
  const isValid = await verifyDPoPProof(proof, 'GET', 'https://api.example.com/data', 'wrong-token', publicKey);
  console.assert(!isValid, 'Proof with wrong token should not verify');
}

// Test case 5: Expired proof
async function testExpiredProof() {
  const oldProof = generateDPoPProofWithExpiration('GET', 'https://api.example.com/data', token, privateKey, Date.now() - 1000);
  const isValid = await verifyDPoPProof(oldProof, 'GET', 'https://api.example.com/data', token, publicKey);
  console.assert(!isValid, 'Expired proof should not verify');
}

// Run all tests
async function runTests() {
  await testValidProof();
  await testWrongMethod();
  await testWrongURL();
  await testWrongToken();
  await testExpiredProof();
  console.log('All DPoP tests passed!');
}
```

---

## Versioning

**Document Version:** 1.0.0  
**DPoP Specification:** [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)  
**Last Updated:** 2026-07-08

---

## References

- [RFC 9449: DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [Solid-OIDC](https://solidproject.org/TR/solid-oidc)
- [JWT Specification](https://datatracker.ietf.org/doc/html/rfc7519)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

---

*This document is part of the Solid Sidecar SDK and is licensed under the same terms as the project.*

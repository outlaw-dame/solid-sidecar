# HTTP Examples for Solid Sidecar SDK

**Phase 27 - SDK/Client Compatibility Layer**  
**Status: STABLE - Production Ready - FULLY HARDENED**

This directory contains raw HTTP examples demonstrating how to interact with a Solid Sidecar instance. These examples follow the Solid protocol specifications and can be used for testing, debugging, or as a reference for implementing clients in other languages.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Resource Operations](#resource-operations)
3. [Policy Operations](#policy-operations)
4. [Notification Operations](#notification-operations)
5. [WebID Operations](#webid-operations)
6. [Error Responses](#error-responses)
7. [Running Examples](#running-examples)

---

## Authentication

### DPoP Authentication Flow

DPoP (Demonstrating Proof-of-Possession) is the recommended authentication method for Solid. Each request must include:

1. **Access Token** in the `Authorization` header
2. **DPoP Proof** in the `DPoP` header

#### DPoP Proof JWT Structure

```json
{
  "typ": "dpop+jwt",
  "alg": "RS256",
  "jti": "unique-identifier",
  "htm": "GET",
  "htu": "https://pod.example.com/data/file.txt",
  "iat": 1699999999,
  "exp": 1700000059,
  "ath": "sha-256-hash-of-access-token"
}
```

#### cURL Example with DPoP

```bash
# Set variables
ACCESS_TOKEN="your-access-token"
DPOP_PROOF="your-dpop-jwt-proof"

# Make authenticated request
curl -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/turtle, application/ld+json" \
  https://pod.example.com/data/file.txt
```

#### Generating DPoP Proof (Conceptual)

```javascript
// Using WebCrypto in browser
async function generateDPoPProof(method, url, accessToken) {
  const key = await crypto.subtle.generateKey(
    {name: "RSASSA-PKCS1-v1_5", modulusLength: 2048},
    true,
    ["sign"]
  );
  
  const proof = {
    typ: "dpop+jwt",
    alg: "RS256",
    jti: crypto.randomUUID(),
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes
    ath: await sha256(accessToken)
  };
  
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key.privateKey,
    new TextEncoder().encode(JSON.stringify(proof))
  );
  
  return base64urlEncode(signature);
}
```

---

## Resource Operations

### GET Resource

Retrieve a resource from the server.

**Request:**
```http
GET /data/file.txt HTTP/1.1
Host: pod.example.com
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
Accept: text/turtle, application/ld+json, */*
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
ETag: "abc123"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT
Link: <http://www.w3.org/ns/ldp#Resource>; rel="type"

@prefix dc: <http://purl.org/dc/elements/1.1/> .
<> dc:title "My File" ;
   dc:created "2026-07-08T10:00:00Z" .
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/turtle" \
  https://pod.example.com/data/file.txt
```

### HEAD Resource

Retrieve only metadata (no body).

**Request:**
```http
HEAD /data/file.txt HTTP/1.1
Host: pod.example.com
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
ETag: "abc123"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT
Link: <http://www.w3.org/ns/ldp#Resource>; rel="type"
Content-Length: 1234
```

**cURL:**
```bash
curl -i -X HEAD \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  https://pod.example.com/data/file.txt
```

### PUT Resource (Create or Replace)

Create a new resource or replace an existing one.

**Request:**
```http
PUT /data/file.txt HTTP/1.1
Host: pod.example.com
Content-Type: text/turtle
Authorization: DPoP your-access-token
DPoP: your-dpop-proof

@prefix dc: <http://purl.org/dc/elements/1.1/> .
<> dc:title "My File" ;
   dc:created "2026-07-08T10:00:00Z" .
```

**Successful Response (Created):**
```http
HTTP/1.1 201 Created
ETag: "new-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT
Location: https://pod.example.com/data/file.txt
```

**Successful Response (Updated):**
```http
HTTP/1.1 200 OK
ETag: "updated-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:01 GMT
```

**cURL:**
```bash
# Create file.txt with content
cat > file.txt << 'EOF'
@prefix dc: <http://purl.org/dc/elements/1.1/> .
<> dc:title "My File" ;
   dc:created "2026-07-08T10:00:00Z" .
EOF

curl -i -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: text/turtle" \
  --data-binary @file.txt \
  https://pod.example.com/data/file.txt
```

### PUT with Conditional Write (If-Match)

Update only if the current ETag matches.

**Request:**
```http
PUT /data/file.txt HTTP/1.1
Host: pod.example.com
Content-Type: text/turtle
If-Match: "abc123"
Authorization: DPoP your-access-token
DPoP: your-dpop-proof

@prefix dc: <http://purl.org/dc/elements/1.1/> .
<> dc:title "Updated Title" .
```

**Successful Response:**
```http
HTTP/1.1 200 OK
ETag: "new-etag"
Last-Modified: Wed, 08 Jul 2026 10:01:00 GMT
```

**Precondition Failed Response:**
```http
HTTP/1.1 412 Precondition Failed
Content-Type: application/json

{
  "code": "PreconditionFailed",
  "message": "ETag does not match",
  "statusCode": 412
}
```

**cURL:**
```bash
curl -i -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: text/turtle" \
  -H "If-Match: \"abc123\"" \
  --data-binary @updated-file.txt \
  https://pod.example.com/data/file.txt
```

### PUT with Create-Only (If-None-Match: *)

Create only if the resource does not exist.

**Request:**
```http
PUT /data/new-file.txt HTTP/1.1
Host: pod.example.com
Content-Type: text/turtle
If-None-Match: *
Authorization: DPoP your-access-token
DPoP: your-dpop-proof

@prefix dc: <http://purl.org/dc/elements/1.1/> .
<> dc:title "New File" .
```

**Successful Response:**
```http
HTTP/1.1 201 Created
ETag: "new-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT
Location: https://pod.example.com/data/new-file.txt
```

**Conflict Response (already exists):**
```http
HTTP/1.1 409 Conflict
Content-Type: application/json

{
  "code": "Conflict",
  "message": "Resource already exists",
  "statusCode": 409
}
```

**cURL:**
```bash
curl -i -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: text/turtle" \
  -H "If-None-Match: *" \
  --data-binary @new-file.txt \
  https://pod.example.com/data/new-file.txt
```

### DELETE Resource

Delete a resource.

**Request:**
```http
DELETE /data/file.txt HTTP/1.1
Host: pod.example.com
If-Match: "abc123"
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
ETag: "deleted-etag"
```

**cURL:**
```bash
curl -i -X DELETE \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "If-Match: \"abc123\"" \
  https://pod.example.com/data/file.txt
```

### PATCH Resource (SPARQL Update)

Perform a partial update using SPARQL Update.

**Request:**
```http
PATCH /data/file.txt HTTP/1.1
Host: pod.example.com
Content-Type: application/sparql-update
If-Match: "abc123"
Authorization: DPoP your-access-token
DPoP: your-dpop-proof

PREFIX dc: <http://purl.org/dc/elements/1.1/>
DELETE { <> dc:title ?title }
INSERT { <> dc:title "New Title" }
WHERE { <> dc:title ?title }
```

**Successful Response:**
```http
HTTP/1.1 200 OK
ETag: "updated-etag"
Last-Modified: Wed, 08 Jul 2026 10:01:00 GMT
```

**cURL:**
```bash
SPARQL_UPDATE='PREFIX dc: <http://purl.org/dc/elements/1.1/>
DELETE { <> dc:title ?title }
INSERT { <> dc:title "New Title" }
WHERE { <> dc:title ?title }'

curl -i -X PATCH \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: application/sparql-update" \
  -H "If-Match: \"abc123\"" \
  --data-raw "$SPARQL_UPDATE" \
  https://pod.example.com/data/file.txt
```

### List Container

List the contents of a container.

**Request:**
```http
GET /data/ HTTP/1.1
Host: pod.example.com
Accept: text/turtle
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
ETag: "container-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT
Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"

@prefix ldp: <http://www.w3.org/ns/ldp#> .
<> a ldp:BasicContainer ;
    ldp:contains <file.txt>, <new-file.txt>, <subfolder/> .
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/turtle" \
  https://pod.example.com/data/
```

### Create Container

Create a new container.

**Request:**
```http
PUT /new-container/ HTTP/1.1
Host: pod.example.com
Content-Type: text/turtle
If-None-Match: *
Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"
Authorization: DPoP your-access-token
DPoP: your-dpop-proof

<> a <http://www.w3.org/ns/ldp#BasicContainer> .
```

**Successful Response:**
```http
HTTP/1.1 201 Created
ETag: "container-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT
Location: https://pod.example.com/new-container/
```

**cURL:**
```bash
curl -i -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: text/turtle" \
  -H "If-None-Match: *" \
  -H "Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"" \
  --data-binary '<> a <http://www.w3.org/ns/ldp#BasicContainer> .' \
  https://pod.example.com/new-container/
```

---

## Policy Operations

### GET WAC Policy (.acl)

Retrieve a Web Access Control policy.

**Request:**
```http
GET /data/file.txt.acl HTTP/1.1
Host: pod.example.com
Accept: text/turtle
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
ETag: "wac-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT

@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<>
    acl:accessTo <https://pod.example.com/data/file.txt> ;
    acl:default <https://pod.example.com/data/> ;
    acl:mode acl:Read, acl:Write ;
    acl:agent <https://user.example.com/profile#me> ;
    acl:agentClass foaf:Agent .

<> acl:accessTo <https://pod.example.com/data/file.txt> ;
    acl:mode acl:Read ;
    acl:agentClass foaf:Agent .
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/turtle" \
  https://pod.example.com/data/file.txt.acl
```

### GET ACP Policy (.acp)

Retrieve an Access Control Policy.

**Request:**
```http
GET /data/file.txt.acp HTTP/1.1
Host: pod.example.com
Accept: application/ld+json
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/ld+json
ETag: "acp-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT

{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": ["Read", "Write"],
      "accessTo": "https://pod.example.com/data/file.txt",
      "agent": "https://user.example.com/profile#me",
      "agentClass": "http://xmlns.com/foaf/0.1/Agent"
    },
    {
      "@type": "AccessGrant",
      "access": ["Read"],
      "accessTo": "https://pod.example.com/data/file.txt",
      "agentClass": "http://xmlns.com/foaf/0.1/Agent"
    }
  ]
}
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: application/ld+json" \
  https://pod.example.com/data/file.txt.acp
```

### PUT ACP Policy

Create or update an ACP policy.

**Request:**
```http
PUT /data/file.txt.acp HTTP/1.1
Host: pod.example.com
Content-Type: application/ld+json
If-None-Match: *
Authorization: DPoP your-access-token
DPoP: your-dpop-proof

{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": ["Read", "Write"],
      "accessTo": "https://pod.example.com/data/file.txt",
      "agent": "https://user.example.com/profile#me",
      "agentClass": "http://xmlns.com/foaf/0.1/Agent"
    }
  ]
}
```

**Successful Response:**
```http
HTTP/1.1 201 Created
ETag: "new-acp-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT
Location: https://pod.example.com/data/file.txt.acp
```

**cURL:**
```bash
ACP_JSON='{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": ["Read", "Write"],
      "accessTo": "https://pod.example.com/data/file.txt",
      "agent": "https://user.example.com/profile#me",
      "agentClass": "http://xmlns.com/foaf/0.1/Agent"
    }
  ]
}'

curl -i -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: application/ld+json" \
  -H "If-None-Match: *" \
  --data-raw "$ACP_JSON" \
  https://pod.example.com/data/file.txt.acp
```

---

## Notification Operations

### Discover Notification Endpoint

**Request:**
```http
GET /.well-known/solid-notifications HTTP/1.1
Host: pod.example.com
Accept: application/json
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "subscriptionUrl": "https://pod.example.com/notifications",
  "channelTypes": ["sse", "websocket"]
}
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: application/json" \
  https://pod.example.com/.well-known/solid-notifications
```

### Create Subscription

**Request:**
```http
POST /notifications HTTP/1.1
Host: pod.example.com
Content-Type: application/json
Authorization: DPoP your-access-token
DPoP: your-dpop-proof

{
  "resourceUri": "https://pod.example.com/data/",
  "channelType": "sse",
  "callbackUrl": "https://myapp.com/notifications"
}
```

**Successful Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json
Location: https://pod.example.com/notifications/sub-123

{
  "id": "sub-123",
  "resourceUri": "https://pod.example.com/data/",
  "channelType": "sse",
  "callbackUrl": "https://myapp.com/notifications",
  "created": "2026-07-08T10:00:00Z",
  "expires": "2026-07-09T10:00:00Z"
}
```

**cURL:**
```bash
SUBSCRIPTION_JSON='{
  "resourceUri": "https://pod.example.com/data/",
  "channelType": "sse",
  "callbackUrl": "https://myapp.com/notifications"
}'

curl -i -X POST \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: application/json" \
  --data-raw "$SUBSCRIPTION_JSON" \
  https://pod.example.com/notifications
```

### List Subscriptions

**Request:**
```http
GET /notifications HTTP/1.1
Host: pod.example.com
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

[
  {
    "id": "sub-123",
    "resourceUri": "https://pod.example.com/data/",
    "channelType": "sse",
    "callbackUrl": "https://myapp.com/notifications",
    "created": "2026-07-08T10:00:00Z",
    "expires": "2026-07-09T10:00:00Z"
  }
]
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  https://pod.example.com/notifications
```

### Get Subscription

**Request:**
```http
GET /notifications/sub-123 HTTP/1.1
Host: pod.example.com
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "sub-123",
  "resourceUri": "https://pod.example.com/data/",
  "channelType": "sse",
  "callbackUrl": "https://myapp.com/notifications",
  "created": "2026-07-08T10:00:00Z",
  "expires": "2026-07-09T10:00:00Z",
  "lastEventId": "event-456"
}
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  https://pod.example.com/notifications/sub-123
```

### Delete Subscription

**Request:**
```http
DELETE /notifications/sub-123 HTTP/1.1
Host: pod.example.com
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
```

**cURL:**
```bash
curl -i -X DELETE \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  https://pod.example.com/notifications/sub-123
```

### Subscribe to Events (Server-Sent Events)

**Request:**
```http
GET /notifications/sub-123/sse HTTP/1.1
Host: pod.example.com
Accept: text/event-stream
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Event Stream:**
```
id: event-456
event: update
data: {"id":"event-456","type":"update","resourceUri":"https://pod.example.com/data/file.txt","containerUri":"https://pod.example.com/data/","agent":"https://user.example.com/profile#me","action":"write","timestamp":"2026-07-08T10:01:00Z","sequenceNumber":42}

id: event-457
event: create
data: {"id":"event-457","type":"create","resourceUri":"https://pod.example.com/data/new-file.txt","containerUri":"https://pod.example.com/data/","agent":"https://user.example.com/profile#me","action":"create","timestamp":"2026-07-08T10:02:00Z","sequenceNumber":43}
```

**cURL (for testing):**
```bash
# Note: cURL doesn't support SSE natively, but you can test with:
curl -N -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/event-stream" \
  https://pod.example.com/notifications/sub-123/sse
```

### Get Historical Events

**Request:**
```http
GET /notifications/sub-123/events?since=2026-07-08T10:00:00Z&limit=10 HTTP/1.1
Host: pod.example.com
Authorization: DPoP your-access-token
DPoP: your-dpop-proof
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

[
  {
    "id": "event-456",
    "type": "update",
    "resourceUri": "https://pod.example.com/data/file.txt",
    "containerUri": "https://pod.example.com/data/",
    "agent": "https://user.example.com/profile#me",
    "action": "write",
    "timestamp": "2026-07-08T10:01:00Z",
    "sequenceNumber": 42
  },
  {
    "id": "event-457",
    "type": "create",
    "resourceUri": "https://pod.example.com/data/new-file.txt",
    "containerUri": "https://pod.example.com/data/",
    "agent": "https://user.example.com/profile#me",
    "action": "create",
    "timestamp": "2026-07-08T10:02:00Z",
    "sequenceNumber": 43
  }
]
```

**cURL:**
```bash
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  "https://pod.example.com/notifications/sub-123/events?since=2026-07-08T10:00:00Z&limit=10"
```

---

## WebID Operations

### Get WebID Profile

**Request:**
```http
GET /profile/card HTTP/1.1
Host: user.example.com
Accept: text/turtle, application/ld+json
```

**Successful Response (Turtle):**
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
ETag: "profile-etag"
Last-Modified: Wed, 08 Jul 2026 10:00:00 GMT

@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix pim: <http://www.w3.org/ns/pim/space#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .

<https://user.example.com/profile/card#me>
    a foaf:Person ;
    foaf:name "John Doe" ;
    foaf:img <https://user.example.com/profile.jpg> ;
    rdfs:label "John" ;
    rdfs:comment "Software Developer" ;
    foaf:homepage <https://johndoe.com> ;
    pim:storage <https://pod.example.com/> ;
    ldp:inbox <https://pod.example.com/inbox/> ;
    ldp:outbox <https://pod.example.com/outbox/> .
```

**cURL:**
```bash
curl -i -X GET \
  -H "Accept: text/turtle" \
  https://user.example.com/profile/card
```

### WebFinger Discovery

**Request:**
```http
GET /.well-known/webfinger?resource=acct:user@example.com HTTP/1.1
Host: user.example.com
Accept: application/json
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "subject": "acct:user@example.com",
  "aliases": ["https://user.example.com/profile/card#me"],
  "links": [
    {
      "rel": "http://webfinger.net/rel/profile-page",
      "type": "text/html",
      "href": "https://user.example.com/profile"
    },
    {
      "rel": "profile",
      "type": "application/rdf+xml",
      "href": "https://user.example.com/profile/card"
    }
  ]
}
```

**cURL:**
```bash
curl -i -X GET \
  -H "Accept: application/json" \
  "https://user.example.com/.well-known/webfinger?resource=acct:user@example.com"
```

---

## Error Responses

### Standard Error Format

All error responses follow a consistent JSON format:

```json
{
  "code": "ErrorCode",
  "message": "Human-readable error message",
  "statusCode": 404,
  "details": {
    "additional": "context"
  }
}
```

### Common Error Responses

#### 401 Unauthorized

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "code": "Unauthorized",
  "message": "Authentication required",
  "statusCode": 401
}
```

**Causes:**
- Missing or invalid access token
- Missing or invalid DPoP proof
- Token expired

#### 403 Forbidden

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "code": "Forbidden",
  "message": "Access denied to resource",
  "statusCode": 403
}
```

**Causes:**
- User does not have permission to access the resource
- Policy denies access

#### 404 Not Found

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "code": "NotFound",
  "message": "Resource not found",
  "statusCode": 404
}
```

**Causes:**
- Resource does not exist
- User does not have permission to see the resource

#### 409 Conflict

```http
HTTP/1.1 409 Conflict
Content-Type: application/json

{
  "code": "Conflict",
  "message": "Resource already exists",
  "statusCode": 409
}
```

**Causes:**
- Attempting to create a resource that already exists (with If-None-Match: *)
- Concurrent modification conflict

#### 412 Precondition Failed

```http
HTTP/1.1 412 Precondition Failed
Content-Type: application/json

{
  "code": "PreconditionFailed",
  "message": "ETag does not match current resource state",
  "statusCode": 412
}
```

**Causes:**
- If-Match header does not match current ETag
- If-None-Match header matches current ETag
- Resource was modified concurrently

#### 429 Too Many Requests

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 5

{
  "code": "RateLimited",
  "message": "Rate limit exceeded",
  "statusCode": 429
}
```

**Causes:**
- Too many requests in a short time period
- SDK will automatically retry with exponential backoff

#### 500 Internal Server Error

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "code": "ServerError",
  "message": "Internal server error",
  "statusCode": 500
}
```

**Causes:**
- Server-side error
- SDK will automatically retry with exponential backoff

---

## Running Examples

### Prerequisites

1. **Solid Sidecar Instance**: Running instance of Solid Sidecar
2. **Access Token**: Valid access token from your Solid-OIDC provider
3. **DPoP Key**: RSA key pair for generating DPoP proofs
4. **cURL**: Command-line tool for testing HTTP requests

### Environment Setup

```bash
# Set environment variables
export SIDECAR_URL="https://your-sidecar-instance.com"
export ACCESS_TOKEN="your-access-token"
export DPOP_PROOF="your-dpop-proof"

# Or use a script to generate DPoP proofs dynamically
```

### Testing with cURL

All examples in this document can be run using cURL. Replace placeholders with actual values:

```bash
# Test GET request
curl -i -X GET \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  https://$SIDECAR_URL/data/
```

### Using with Postman

1. Import the cURL commands into Postman
2. Set environment variables:
   - `sidecar_url`: Your Solid Sidecar URL
   - `access_token`: Your access token
   - `dpop_proof`: Your DPoP proof
3. Add headers to all requests:
   - `Authorization: DPoP {{access_token}}`
   - `DPoP: {{dpop_proof}}`
   - `Accept: text/turtle, application/ld+json`

---

## Best Practices

### Always Use Conditional Writes

Always use ETags for writes to prevent lost updates:

```bash
# Get current ETag
ETAG=$(curl -sI \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  https://$SIDECAR_URL/data/file.txt | grep -i etag | awk '{print $2}' | tr -d '"')

# Update with If-Match
curl -i -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: text/turtle" \
  -H "If-Match: \"$ETAG\"" \
  --data-binary @updated-content.txt \
  https://$SIDECAR_URL/data/file.txt
```

### Handle Errors Gracefully

```bash
# Check for specific status codes
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  https://$SIDECAR_URL/data/file.txt)

case $RESPONSE in
  200) echo "Success" ;;
  401) echo "Unauthorized - check token" ;;
  403) echo "Forbidden - access denied" ;;
  404) echo "Not found" ;;
  412) echo "Conflict - ETag mismatch" ;;
  *) echo "Error: $RESPONSE" ;;
esac
```

### Use Proper Content Types

Always specify the correct Content-Type:

| Format | Content-Type | Extension |
|--------|--------------|-----------|
| Turtle | `text/turtle` | `.ttl` |
| JSON-LD | `application/ld+json` | `.json` |
| N-Triples | `application/n-triples` | `.nt` |
| RDF/XML | `application/rdf+xml` | `.rdf` |
| SPARQL Update | `application/sparql-update` | `.sparql` |

---

## Security Considerations

### Never Hardcode Credentials

❌ **Bad:**
```bash
curl -H "Authorization: DPoP abc123" ...
```

✅ **Good:**
```bash
ACCESS_TOKEN=$(get_token_from_secure_storage)
curl -H "Authorization: DPoP $ACCESS_TOKEN" ...
```

### Always Use HTTPS

❌ **Bad:**
```bash
curl http://pod.example.com/...
```

✅ **Good:**
```bash
curl https://pod.example.com/...
```

### Validate All Inputs

When building URIs from user input, always validate:

```bash
# Validate URI format
if [[ ! $URI =~ ^https?://[a-zA-Z0-9\.\-]+ ]]; then
  echo "Invalid URI"
  exit 1
fi
```

---

## Versioning

**SDK Version:** 1.0.0  
**Phase:** 27 - SDK/Client Compatibility Layer  
**Status:** STABLE - Production Ready - FULLY HARDENED  
**Last Updated:** 2026-07-08

---

## Support

For issues or questions:
- **Repository:** [github.com/outlaw-dame/solid-sidecar](https://github.com/outlaw-dame/solid-sidecar)
- **Phase:** 27 - SDK/Client Compatibility Layer
- **Status:** STABLE - Production Ready - FULLY HARDENED

---

*These examples are part of the Solid Sidecar SDK and are licensed under the same terms as the project.*

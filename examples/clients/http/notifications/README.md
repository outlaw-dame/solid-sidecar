# Notifications Examples

**Phase**: 27 - SDK/Client Compatibility Layer  
**Component**: Notifications  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Status**: STABLE - Production Ready  

---

## Overview

This directory contains examples for **Solid Notifications** with Solid Sidecar. Solid Notifications provide real-time updates about changes to resources in a user's Pod.

**Important**: Notifications in Solid Sidecar follow the [Solid Notifications Protocol](https://solidproject.org/TR/notifications-protocol) and are **privacy-safe** by default.

---

## Notification Models

Solid Sidecar supports multiple notification delivery mechanisms:

| Mechanism | Description | Status |
|-----------|-------------|--------|
| Server-Sent Events (SSE) | Standard HTTP streaming | STABLE |
| WebSockets | Full-duplex communication | EXPERIMENTAL |
| Polling | Periodic polling (fallback) | STABLE |

---

## Notification Types

The following event types are supported:

| Event Type | Description | Trigger |
|------------|-------------|---------|
| `ResourceCreated` | Resource was created | PUT on non-existing resource |
| `ResourceUpdated` | Resource was updated | PUT/PATCH on existing resource |
| `ResourceDeleted` | Resource was deleted | DELETE on existing resource |
| `ContainerCreated` | Container was created | PUT on non-existing container |
| `ContainerUpdated` | Container was updated | PUT/PATCH on existing container |
| `ContainerDeleted` | Container was deleted | DELETE on existing container |
| `PolicyCreated` | Policy was created | PUT on new policy resource |
| `PolicyUpdated` | Policy was updated | PUT/PATCH on existing policy |
| `PolicyDeleted` | Policy was deleted | DELETE on existing policy |

---

## Files in This Directory

| File | Description | Mechanism |
|------|-------------|-----------|
| [subscribe-sse.sh](./subscribe-sse.sh) | Subscribe using Server-Sent Events | SSE |
| [subscribe-websocket.sh](./subscribe-websocket.sh) | Subscribe using WebSockets | WebSocket |
| [reconnect-resume.sh](./reconnect-resume.sh) | Reconnect with cursor resume | SSE/WebSocket |
| [resync-after-gap.sh](./resync-after-gap.sh) | Resync after missed events | Both |

---

## Server-Sent Events (SSE)

SSE is a standard HTTP mechanism for server push notifications. It uses a single, long-lived HTTP connection.

### SSE Subscription Flow

```
Client                           Server
   |                               |
   |-- GET /notifications ------->|  (SSE connection)
   |                               |
   |<-- Event: ResourceCreated --|  (Resource was created)
   |                               |
   |<-- Event: ResourceUpdated --|  (Resource was modified)
   |                               |
   |<-- Event: ResourceDeleted --|  (Resource was deleted)
   |                               |
   |-- (Connection closed) ------>|  (Client disconnects)
```

### SSE Request

```http
GET /notifications?resource=https://sidecar.example.com/container/ HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Accept: text/event-stream
Last-Event-ID: cursor-123  # Optional: resume from specific event
```

### SSE Response

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

Event: ResourceCreated
id: event-abc-123
Data: {"resource": "https://sidecar.example.com/container/resource.ttl", "type": "ResourceCreated", "timestamp": "2026-07-07T00:00:00Z", "agent": "https://alice.webid"}

Event: ResourceUpdated
id: event-def-456
data: {"resource": "https://sidecar.example.com/container/resource.ttl", "type": "ResourceUpdated", "timestamp": "2026-07-07T00:01:00Z", "agent": "https://alice.webid"}

```

---

## WebSocket Notifications

WebSockets provide full-duplex communication for notifications.

### WebSocket Subscription Flow

```
Client                           Server
   |                               |
   |-- WebSocket /notifications --->|  (WebSocket connection)
   |                               |
   |-- Subscribe: resource=URI -->|  (Subscribe to resource)
   |                               |
   |<-- Event: ResourceCreated --|  (Resource was created)
   |                               |
   |<-- Event: ResourceUpdated --|  (Resource was modified)
   |                               |
   |-- Unsubscribe: cursor=X --->|  (Unsubscribe)
   |                               |
   |-- Close -------------------->|  (Close connection)
```

### WebSocket Connection

```javascript
// JavaScript example
const socket = new WebSocket('wss://sidecar.example.com/notifications');

socket.onopen = () => {
    // Subscribe to resource
    socket.send(JSON.stringify({
        action: 'subscribe',
        resource: 'https://sidecar.example.com/container/'
    }));
};

socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Event:', data.type, 'on', data.resource);
};

socket.onclose = () => {
    console.log('Connection closed');
};
```

---

## Event Structure

All notification events have the following structure:

```json
{
  "id": "unique-event-id",
  "type": "ResourceCreated" | "ResourceUpdated" | "ResourceDeleted" | "ContainerCreated" | "ContainerUpdated" | "ContainerDeleted" | "PolicyCreated" | "PolicyUpdated" | "PolicyDeleted",
  "resource": "https://sidecar.example.com/container/resource.ttl",
  "container": "https://sidecar.example.com/container/",
  "timestamp": "2026-07-07T00:00:00Z",
  "agent": "https://alice.webid",
  "metadata": {},
  "sequence": 12345
}
```

### Event Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for this event |
| `type` | string | Type of event (see Notification Types) |
| `resource` | string | URI of the affected resource |
| `container` | string | URI of the containing container |
| `timestamp` | string | ISO 8601 timestamp of the event |
| `agent` | string | WebID of the agent that caused the change |
| `metadata` | object | Additional event-specific metadata |
| `sequence` | number | Monotonically increasing sequence number |

---

## Cursor-Based Resume

To handle connection interruptions and missed events, clients can use cursor-based resume:

1. **Store the last received event ID** when the connection is active
2. **Use `Last-Event-ID` header (SSE)** or `cursor` parameter to resume
3. **Request missed events** if the server supports replay

### Resume with SSE

```http
GET /notifications?resource=URI&cursor=last-event-id HTTP/1.1
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Accept: text/event-stream
```

### Resume with WebSocket

```json
{
  "action": "subscribe",
  "resource": "https://sidecar.example.com/container/",
  "cursor": "last-event-id"
}
```

---

## Security Considerations

### Authentication

1. **DPoP authentication required** for all notification subscriptions
2. **Token must be valid** for the duration of the subscription
3. **Refresh tokens** before they expire to maintain subscriptions

### Authorization

1. **Verify subscription permissions** - agent must have read access to the resource
2. **Filter events** based on agent's access permissions
3. **Never expose private data** in notifications

### Privacy

1. **Filter sensitive events** - don't send notifications about resources the agent can't access
2. **Rate limit notifications** - prevent DoS via notification flooding
3. **Use HTTPS/WSS** - always encrypt notification traffic

### Validation

1. **Validate resource URIs** to prevent SSRF
2. **Validate event types** are known and allowed
3. **Validate agent URIs** in events

---

## Error Handling

### SSE Errors

SSE connections can fail with:

| Status Code | Error | Action |
|-------------|-------|--------|
| 401 | Unauthorized | Re-authenticate and reconnect |
| 403 | Forbidden | Check permissions |
| 404 | Not Found | Resource doesn't exist |
| 429 | Too Many Requests | Wait and retry |
| 500 | Server Error | Retry with backoff |

### WebSocket Errors

WebSocket connections can fail with:

| Code | Reason | Action |
|------|--------|--------|
| 1000 | Normal Closure | Reconnect if needed |
| 1001 | Going Away | Reconnect with backoff |
| 1008 | Policy Violation | Check request format |
| 1009 | Message Too Big | Reduce message size |
| 1011 | Internal Error | Retry with backoff |
| 4000-4999 | Application Errors | Check error message |

---

## Retry and Backoff

Implement exponential backoff for reconnection:

```javascript
let retryCount = 0;
const maxRetries = 5;
const baseDelay = 1000; // 1 second

function connect() {
    const delay = Math.min(baseDelay * Math.pow(2, retryCount), 30000); // Max 30s
    
    try {
        // Connect
        retryCount = 0;
    } catch (error) {
        retryCount++;
        if (retryCount >= maxRetries) {
            throw error;
        }
        setTimeout(connect, delay + Math.random() * 100); // Add jitter
    }
}
```

---

## Testing

Test your notification implementation with:

1. **Resource creation** - should trigger ResourceCreated event
2. **Resource update** - should trigger ResourceUpdated event
3. **Resource deletion** - should trigger ResourceDeleted event
4. **Container operations** - should trigger Container* events
5. **Policy changes** - should trigger Policy* events
6. **Connection interruption** - should allow resume from cursor
7. **Authentication failure** - should close connection with 401
8. **Authorization failure** - should close connection with 403
9. **Multiple subscribers** - should receive independent event streams
10. **Rate limiting** - should respect rate limits

---

## References

- [Solid Notifications Protocol](https://solidproject.org/TR/notifications-protocol)
- [Server-Sent Events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- [WebSocket API](https://datatracker.ietf.org/doc/html/rfc6455)
- [Client Contract](../../docs/client-contract.md)
- [Client Security Requirements](../../docs/client-security.md)

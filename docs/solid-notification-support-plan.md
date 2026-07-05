# Solid Notification Support Plan

## Overview

This document outlines the notification support plan for the Solid runtime as part of Phase 16: Notifications, live updates, and indexing. The goal is to provide modern application performance capabilities while maintaining strict privacy and security guarantees.

## Architecture

### Notification Layer

The notification layer (`internal/runtime/notification.go`) implements a pub/sub system for Solid resource events with the following characteristics:

1. **Event Types**: Create, Update, Delete, Move, Copy, Access, Policy, Container, Custom
2. **Privacy-Safe**: No sensitive data (resource bodies, policy content, credentials) in notifications
3. **Channel-Based**: Subscribers can subscribe to specific channels with URI patterns
4. **Filtering**: Subscribers can apply filters based on event types, resource URIs, containers, agents
5. **Reconnection Support**: Event buffering for reconnecting subscribers
6. **Metrics**: Full observability for event delivery, failures, and lag

### Resource Index Layer

The resource index layer (`internal/runtime/indexing.go`) provides:

1. **Container Metadata Index**: Maps container URIs to contained resources
2. **Agent/WebID Index**: Maps WebIDs to resources they have access to
3. **Type Index**: Maps resource types (RDF types, content types) to resources
4. **Full-Text Index**: Limited to public/metadata content only (no private body indexing)
5. **Access Control Index**: Tracks access control information for resources

### Metadata Index Layer

The metadata index layer (`internal/runtime/metadata.go`) provides:

1. **Resource Metadata**: URI-based lookup of resource metadata
2. **Type-Based Queries**: Find resources by content type
3. **WebID-Scoped Access**: Index resources by WebID with privacy filtering
4. **Container Listing**: List resources within containers

## Integration Points

### Event Flow

```
Resource Change (Create/Update/Delete)
       ↓
Storage Layer (stores resource)
       ↓
Metadata Index Layer (updates metadata indexes)
       ↓
Resource Index Layer (updates search indexes)
       ↓
Notification Layer (publishes event to subscribers)
       ↓
Subscribers (receive privacy-safe event notifications)
```

### Event Stream

The event stream connects resource changes to the notification system:

1. **Storage Layer Integration**: When a resource is created, updated, or deleted, the storage layer emits a ResourceChangeEvent
2. **Metadata Index Update**: The metadata index layer listens for storage events and updates its indexes
3. **Resource Index Update**: The resource index layer receives metadata updates and maintains search indexes
4. **Notification Publication**: The notification layer receives index update events and publishes to subscribers

## Privacy and Security Requirements

### No Private Content Leakage

1. **Notification Events**: Only contain metadata (URI, type, timestamps, agent references) - NEVER resource bodies
2. **Index Content**: Full-text indexing is limited to public resources and metadata only
3. **Access Filtering**: All index queries respect access control policies
4. **Agent Scoping**: Index results are filtered by WebID/agent access

### Data Classification

**Public Data (Safe for Notifications/Indexing):**
- Resource URIs
- Resource types (RDF types, content types)
- Metadata (size, timestamps, ETags)
- Container URIs
- Agent/WebID references
- Event types
- Access mode (public, authenticated, private)

**Private Data (NEVER in Notifications/Indexing):**
- Resource bodies/content
- Policy document content
- Authentication tokens
- DPoP proofs
- Private metadata
- Sensitive headers

### WebID-Scoped Index Access

The index layers implement WebID-scoped access through:

1. **Agent Index**: Maps WebID → [resource URIs they can access]
2. **Access Control Integration**: `hasAccess(resourceURI, webID, includePrivate)` method
3. **Filtering**: Query results are filtered based on the requesting agent's access

### Policy-Aware Filtering

Index queries respect policy through:

1. **Access Info Index**: Tracks access control information for each resource
2. **hasAccess Method**: Checks if an agent has access to a resource
3. **Private Resource Exclusion**: Private resources are excluded from results unless explicitly requested and authorized
4. **Group Membership**: Supports group-based access control

## Implementation Status

### Completed (Existing)

1. ✅ Notification layer with pub/sub architecture
2. ✅ Resource index layer with container, agent, type indexes
3. ✅ Metadata index layer with URI, type, WebID queries
4. ✅ Privacy-safe event types (no body content)
5. ✅ WebID-scoped index access
6. ✅ Policy-aware filtering (hasAccess method)
7. ✅ Metrics for observability

### Required for Phase 16 Completion

1. 🟡 **Event Stream Integration**: Connect storage → metadata → index → notification layers
2. 🟡 **Container Metadata Index**: Already exists in metadata.go, needs integration
3. 🟡 **WebID-Scoped Index Access**: Enhance with explicit WebID filtering
4. 🟡 **Policy-Aware Index Filtering**: Complete implementation with tests
5. 🟡 **Private Content Protection**: Verify no private bodies in indexes/notifications
6. 🟡 **Event Lag and Dropped Events Metrics**: Add to existing metrics

## API Design

### Notification API

```go
// Subscribe to resource changes
subscription, err := notificationLayer.Subscribe(ctx, "resource-updates", filter)
defer notificationLayer.Unsubscribe(subscription)

for event := range subscription.EventChannel {
    // Handle event (contains URI, type, metadata only - no body)
    fmt.Printf("Resource %s changed: %s\n", event.ResourceURI, event.EventType)
}
```

### Index Query API

```go
// Query with WebID scoping
results, err := indexLayer.Search(IndexQuery{
    Query:       "search term",
    WebID:       "https://user.example/webid#me",
    IncludePrivate: false, // Exclude private resources by default
    ContainerURI: "https://pod.example/data/",
})
```

### Metadata Query API

```go
// Get resources by WebID
uris, err := metadataLayer.GetResourcesByWebID("https://user.example/webid#me")

// Get container contents
resources, err := metadataLayer.ListContainer("https://pod.example/data/")
```

## Testing Requirements

1. **Privacy Tests**: Verify no private content appears in notifications or indexes
2. **Access Control Tests**: Verify index results respect access policies
3. **WebID Scoping Tests**: Verify queries return only authorized resources
4. **Event Delivery Tests**: Verify events are delivered with proper filtering
5. **Metrics Tests**: Verify event lag and dropped event metrics are tracked
6. **Concurrency Tests**: Verify thread-safe operation with race detection
7. **Memory Tests**: Verify bounded memory usage with circuit breakers

## Acceptance Criteria

- [ ] Clients can observe resource changes through documented mechanisms
- [ ] Index results respect authorization
- [ ] Private content does not leak through metadata indexes
- [ ] Event lag is measured and observable
- [ ] Dropped events are tracked and observable
- [ ] WebID-scoped queries work correctly
- [ ] Policy-aware filtering is enforced

## Next Steps

1. Implement event stream integration between layers
2. Add comprehensive tests for privacy and access control
3. Document notification API for Solid client developers
4. Add event lag and dropped event metrics
5. Verify all acceptance criteria are met

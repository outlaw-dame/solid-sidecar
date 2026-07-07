# Policy Resource Examples

**Phase**: 27 - SDK/Client Compatibility Layer  
**Component**: Policy Operations  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Status**: STABLE - Production Ready  

---

## Overview

This directory contains examples for **Solid access control policies** (WAC and ACP) with Solid Sidecar. These examples demonstrate how to create, read, and manage access control policies that determine who can access which resources.

**Important**: Policy enforcement in Solid Sidecar is **shadow mode by default**. The sidecar observes but does NOT enforce policy decisions. Community Solid Server (CSS) remains the authority for access control enforcement.

---

## Access Control Models

Solid Sidecar supports the following access control models:

| Model | Description | Format | Status |
|-------|-------------|--------|--------|
| WAC | Web Access Control - Original Solid access control | RDF/Turtle | STABLE |
| ACP | Access Control Policy - Newer, more flexible model | RDF/Turtle or JSON-LD | STABLE |
| SAI | Solid Application Interoperability | Various | EXPERIMENTAL |

---

## WAC (Web Access Control)

WAC is the original access control model for Solid. It uses RDF triples to define access rules.

### WAC Policy Structure

A WAC policy resource typically contains:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#owner>
    a acl:Authorization;
    acl:accessTo <resource>;
    acl:agent <https://alice.webid>;
    acl:mode acl:Read, acl:Write, acl:Control.

<#public>
    a acl:Authorization;
    acl:accessTo <resource>;
    acl:agentClass foaf:Agent;
    acl:mode acl:Read.
```

### WAC Access Modes

| Mode | Description | RDF URI |
|------|-------------|---------|
| Read | Allows reading the resource | `acl:Read` |
| Write | Allows modifying the resource | `acl:Write` |
| Control | Allows modifying the ACL | `acl:Control` |
| Append | Allows appending to the resource | `acl:Append` |

---

## ACP (Access Control Policy)

ACP is a newer, more flexible access control model that provides fine-grained permissions.

### ACP Policy Structure

An ACP policy resource typically contains:

```turtle
@prefix acl: <http://www.w3.org/ns/solid/acp#> .

<#policy>
    a acl:AccessPolicy;
    acl:appliesTo <resource>;
    acl:allow [
        acl:actor <https://alice.webid>;
        acl:operation acl:Read, acl:Write, acl:Control
    ];
    acl:deny [
        acl:actor <https://evil.webid>;
        acl:operation acl:Write
    ].
```

### ACP Operations

| Operation | Description | RDF URI |
|-----------|-------------|---------|
| Read | Read resource | `acl:Read` |
| Write | Modify resource | `acl:Write` |
| Control | Modify ACL | `acl:Control` |
| Append | Append to resource | `acl:Append` |
| Create | Create resources in container | `acl:Create` |
| Delete | Delete resources | `acl:Delete` |

---

## Files in This Directory

| File | Description | Access Control Model |
|------|-------------|----------------------|
| [wac-read-write-example.ttl](./wac-read-write-example.ttl) | Basic WAC read/write policy | WAC |
| [wac-append-example.ttl](./wac-append-example.ttl) | WAC with append-only access | WAC |
| [wac-public-read.ttl](./wac-public-read.ttl) | WAC with public read access | WAC |
| [acp-example.ttl](./acp-example.ttl) | Basic ACP policy | ACP |
| [acp-fine-grained.ttl](./acp-fine-grained.ttl) | Fine-grained ACP with allow/deny | ACP |
| [verify-policy.sh](./verify-policy.sh) | Verify policy enforcement | Both |

---

## Policy Resource Locations

Policy resources are typically stored alongside the resources they control:

```
resource.ttl           <- The actual resource
resource.ttl.acl      <- WAC policy for resource.ttl
resource.ttl.meta     <- Metadata for resource.ttl (may contain ACP references)

container/
  resource1.ttl
  resource1.ttl.acl   <- WAC policy for resource1.ttl
  .acl               <- Default WAC policy for container/
  .meta              <- Container metadata (may contain ACP)
```

---

## Creating WAC Policies

### Basic WAC Policy (Read/Write for Owner)

This policy grants the owner full access to a resource:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .

<> a acl:Authorization;
    acl:accessTo </resource.ttl>;
    acl:agent <https://alice.webid>;
    acl:mode acl:Read, acl:Write, acl:Control.
```

### Public Read Access

This policy allows anyone to read the resource:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<> a acl:Authorization;
    acl:accessTo </resource.ttl>;
    acl:agentClass foaf:Agent;
    acl:mode acl:Read.
```

### Group Access

This policy grants access to members of a specific group:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .

<> a acl:Authorization;
    acl:accessTo </resource.ttl>;
    acl:agentGroup <https://example.org/groups/friends>;
    acl:mode acl:Read, acl:Write.
```

---

## Creating ACP Policies

### Basic ACP Policy

```turtle
@prefix acl: <http://www.w3.org/ns/solid/acp#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .

<> a acl:AccessPolicy;
    acl:appliesTo </resource.ttl>;
    acl:allow [
        acl:actor <https://alice.webid>;
        acl:operation acl:Read, acl:Write, acl:Control
    ].
```

### Public Read with ACP

```turtle
@prefix acl: <http://www.w3.org/ns/solid/acp#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<> a acl:AccessPolicy;
    acl:appliesTo </resource.ttl>;
    acl:allow [
        acl:actorClass foaf:Agent;
        acl:operation acl:Read
    ].
```

### Fine-Grained ACP with Allow/Deny

```turtle
@prefix acl: <http://www.w3.org/ns/solid/acp#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<> a acl:AccessPolicy;
    acl:appliesTo </resource.ttl>;
    
    # Allow owner full access
    acl:allow [
        acl:actor <https://alice.webid>;
        acl:operation acl:Read, acl:Write, acl:Control, acl:Delete
    ];
    
    # Allow friends read/write
    acl:allow [
        acl:actorGroup <https://alice.webid#friends>;
        acl:operation acl:Read, acl:Write
    ];
    
    # Allow public read
    acl:allow [
        acl:actorClass foaf:Agent;
        acl:operation acl:Read
    ];
    
    # Explicitly deny evil actor
    acl:deny [
        acl:actor <https://evil.webid>;
        acl:operation acl:Read, acl:Write, acl:Control
    ].
```

---

## Policy Inheritance

Policies can be inherited from parent containers:

1. **Container-level policies** apply to all resources in that container
2. **Resource-specific policies** override container-level policies
3. **Deny rules** take precedence over allow rules

---

## Security Considerations

### Policy Validation

1. **Always validate policy URIs** to prevent SSRF attacks
2. **Check policy ownership** - only owners should be able to modify policies
3. **Validate agent URIs** - ensure they are valid WebIDs
4. **Limit policy complexity** - prevent excessively complex policies

### Policy Storage

1. **Store policies securely** - policies are sensitive resources
2. **Use proper access control** on policy resources themselves
3. **Log policy changes** for auditing

### Policy Evaluation

1. **Shadow mode behavior** - by default, policies are observed but not enforced
2. **CSS remains authority** - CSS makes the final enforcement decision
3. **Cache policy decisions** for performance, but invalidate on changes

---

## Testing Policies

Test your policy implementation with:

1. **Owner access** - owner should have full access
2. **Public access** - public should only have read access (if configured)
3. **Group access** - group members should have appropriate access
4. **Denied access** - denied agents should not have access
5. **Inherited policies** - child resources should inherit parent policies
6. **Policy override** - resource-specific policies should override container policies

---

## Examples

### Grant Read Access to a Specific Person (WAC)

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<> a acl:Authorization;
    acl:accessTo </resource.ttl>;
    acl:agent <https://bob.webid>;
    acl:mode acl:Read.
```

### Grant Read/Write Access to a Group (WAC)

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<> a acl:Authorization;
    acl:accessTo </resource.ttl>;
    acl:agentGroup <https://example.org/groups/editors>;
    acl:mode acl:Read, acl:Write.
```

### Grant Public Read Access (WAC)

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<> a acl:Authorization;
    acl:accessTo </resource.ttl>;
    acl:agentClass foaf:Agent;
    acl:mode acl:Read.
```

### Grant Full Access with ACP

```turtle
@prefix acl: <http://www.w3.org/ns/solid/acp#> .

<> a acl:AccessPolicy;
    acl:appliesTo </resource.ttl>;
    acl:allow [
        acl:actor <https://alice.webid>;
        acl:operation acl:Read, acl:Write, acl:Control, acl:Delete
    ].
```

---

## References

- [WAC Specification](https://github.com/solid/solid-spec/blob/master/specification/protocols/acl.md)
- [ACP Specification](https://github.com/solid/solid-spec/blob/master/specification/protocols/acp.md)
- [Solid Protocol](https://solidproject.org/TR/protocol)
- [Client Contract](../../docs/client-contract.md)
- [Client Security Requirements](../../docs/client-security.md)

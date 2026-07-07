# SAI Support Decision

**Status: Phase 40 - Documentation Reconciliation in Progress**

This document describes the Solid Application Interoperability (SAI) support decision and current implementation state for the solid-sidecar project. **IMPORTANT: This document is being updated as part of Phase 40 to resolve a documentation contradiction identified in the repository audit.**

## Overview

Solid Application Interoperability (SAI) is a Solid specification for application interoperability that defines how Solid applications can describe their capabilities, register with Solid servers, and interact with data in a standardized way.

## Current State - UPDATED Phase 40

**DOCUMENTATION CONTRACTION RESOLVED:**

Previous versions of this document stated "SAI support is NOT YET IMPLEMENTED", but the repository audit (`docs/repository-audit-2026-07-02.md`) discovered substantial SAI implementation in the codebase.

### Actual Current Implementation

As of Phase 39.5, solid-sidecar supports:
- **WAC (Web Access Control)**: 🟢 Full parser and evaluator in shadow mode
- **ACP (Access Control Policy)**: 🟢 Full parser and evaluator in shadow mode  
- **CSS Compatibility**: 🟢 Full reverse-proxy compatibility with Community Solid Server
- **SAI Service**: 🟡 **SERVICE IMPLEMENTATION EXISTS** - Comprehensive SAI service implementation

### SAI Implementation Details

**IMPLEMENTATION STATUS: Service-Complete, Enforcement-Not-Authoritative**

The following SAI components **DO EXIST** in the codebase:

- **`internal/sai/service.go`**: Full SAI service implementation
- **SAI Models**: Application, Registration, Access Grant, Data Registration, Data Grant, Data Instance, Shape Tree, Authorization Agent
- **Storage-backed flows**: Complete service implementation with storage integration
- **Feature Flag Design**: Prepared boundary with explicit configuration controls

### Clarified Decision: Service Implementation vs Enforcement Authority

**REVISED Decision**: 

1. **SAI Service Implementation**: ✅ **COMPLETE** - SAI service scaffolding and infrastructure exists
2. **SAI Enforcement Semantics**: ❌ **DEFERRED** - SAI-based authorization enforcement remains explicitly deferred

The distinction is critical: **The SAI service exists and can be used for application interoperability, but SAI-based authorization decisions are NOT production-authoritative.**

## Enforcement Deferral Rationale

SAI **authorization enforcement** is **EXPLICITLY DEFERRED** until the following conditions are met:

1. **Documented Semantics**: SAI semantics must be fully documented in an official Solid specification or W3C draft that this project can reference.
2. **Interoperability Evidence**: At least two independent Solid server implementations must demonstrate interoperable SAI behavior.
3. **Test Fixtures**: A comprehensive set of SAI test fixtures must be available and reviewed by the project maintainers.
4. **Security Review**: SAI security properties must be independently reviewed with no identified vulnerabilities in the inference model.
5. **Shadow-Only First**: Any SAI implementation must start in shadow mode with explicit configuration gates.

## Rationale for Enforcement Deferral

**Note: The rationale below applies to SAI **authorization enforcement**, NOT to the SAI service implementation which already exists.**

### 1. Specification Maturity for Enforcement

While SAI specifications exist for application interoperability, **SAI authorization inference semantics** (if that was the intended meaning) may not have a stable, widely-implemented specification. Implementing SAI-based authorization enforcement before specification stabilization risks:

- **Breaking Changes**: Authorization implementation would need significant rewrites as the spec evolves
- **Incompatibility**: Different Solid servers would implement different SAI authorization variants
- **Security Gaps**: Undiscovered edge cases in inference model could lead to authorization bypasses

### 2. Authorization Complexity

SAI authorization enforcement would add significant complexity:

- **Inference Engine**: Would require forward-chaining or backward-chaining inference engine
- **Rule Conflict Resolution**: Must define deterministic conflict resolution for competing inferences
- **Performance**: Inference can be computationally expensive, requiring caching and optimization
- **Debugging**: Authorization decisions become harder to explain and debug

The current WAC and ACP implementations cover the vast majority of Solid use cases without the complexity of inference-based authorization.

### 3. Existing Authorization Coverage

WAC and ACP already provide comprehensive authorization:
- Direct access grants and denials
- Agent and agent class matching
- Mode-based access control (read, write, append, control)
- Container inheritance
- Public access
- Group membership (via agentClass)

**Clarification**: The SAI implementation in this project appears to be for **Solid Application Interoperability** (application description, registration, etc.) rather than **Solid Authorization Inference** (inference-based authorization). The service implementation supports application interoperability features, not authorization inference.

### 4. Risk Profile for Enforcement

If SAI authorization inference were to be implemented, it would introduce new security risks:

- **Inference Attacks**: Malicious policies could craft inference chains that cause denial of service
- **Rule Interaction**: Complex rule interactions could lead to unintended access grants
- **Debugging Complexity**: Security audits become more difficult with inferred permissions
- **Implementation Bugs**: Any bug in the inference engine could have authorization-wide impact

## Implementation Status - UPDATED Phase 40

### What Exists (Service Implementation) ✅

The following SAI components **ARE IMPLEMENTED** in the codebase:

- **Service Layer**: `internal/sai/service.go` with comprehensive storage-backed flows
- **Data Models**: Application, Registration, AccessGrant, DataRegistration, DataGrant, DataInstance, ShapeTree, AuthorizationAgent
- **Storage Integration**: Full storage-backed implementation
- **Feature Flags**: Prepared boundary with explicit configuration controls

### What is Deferred (Authorization Enforcement) ⏳

The following **REMAINS DEFERRED**:

- **SAI Authorization Inference**: Inference-based authorization decisions
- **SAI Parser/Evaluator**: If SAI is meant to be an authorization mechanism (separate from application interoperability)
- **Production Authorization**: SAI-based authorization enforcement in production

## Prepared Boundary for Future Authorization SAI (if needed)

To ensure SAI can be added when ready, the following boundary has been prepared:

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Authorization Layer                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │  WAC        │  │  ACP        │  │  SAI (DEFERRED) │ │
│  │  Parser     │  │  Parser     │  │  Parser          │ │
│  │  Evaluator │  │  Evaluator │  │  Evaluator       │ │
│  └─────────────┘  └─────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Aggregator        │
                    │  (Shadow Mode)     │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Enforcement Gate  │
                    │  (Shadow by Default)│
                    └───────────────────┘
```

### Feature Flag

SAI support, when implemented, will be behind an explicit feature flag:

```yaml
# config.yaml
authz:
  sai:
    enabled: false  # Default: false (deferred)
    shadowMode: true  # Default: true (non-enforcing)
```

### Interface Design

The SAI parser will implement the existing `RDFParser` interface for consistency:

```go
type SAIParser struct {
    // Implements RDFParser interface
    options   SAIParserOptions
    rdfParser *RDFParserRegistry
}

func (p *SAIParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error)
func (p *SAIParser) SupportedContentTypes() []string
```

The SAI evaluator will implement the existing `Evaluator` interface:

```go
type SAIEvaluator struct {
    options    SAIEvaluatorOptions
    parser     *SAIParser
    RDFParser  *RDFParserRegistry
    shadowMode bool
}

func (e *SAIEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error)
```

### Types Design

When SAI is implemented, it will use the following type hierarchy:

```go
// SAIPolicy represents a complete SAI policy document
type SAIPolicy struct {
    PolicyURI    string
    ResourceURI  string
    Rules       []SAIRule
    Inherit     bool
    Owner       string
}

// SAIRule represents a single SAI rule
type SAIRule struct {
    Premise    SAIPremise   // Conditions that must be true
    Conclusion SAIConclusion // Authorization decision
    Priority   int          // Rule priority for conflict resolution
}

// SAIPremise represents the conditions for a rule
type SAIPremise struct {
    Agent       string      // Agent or agent class
    Resource    string      // Resource or resource class
    Mode        AccessMode  // Access mode
    Context     string      // Context conditions
}

// SAIConclusion represents the conclusion of a rule
type SAIConclusion struct {
    Allows      bool        // Allow or deny
    Mode        AccessMode  // Granted mode(s)
    Delegation  string      // Delegation chain
}
```

### Test Fixtures

SAI test fixtures will follow the same pattern as WAC and ACP fixtures:

```json
{
  "schemaVersion": "authz.v1",
  "request": {
    "requestID": "sai-test-001",
    "method": "GET",
    "resourceURI": "https://example.org/resource",
    "agentWebID": "https://example.org/alice#webid",
    "requestedModes": ["read"],
    "policyDocuments": [...]
  },
  "decision": {
    "decision": "allow",
    "reasonCode": "saiInferenceAllow",
    "reasonDetail": "Inferred from delegation chain"
  }
}
```

## Acceptance Criteria for Future Authorization Implementation

**Note: These criteria apply only if SAI authorization inference is to be implemented in the future. The SAI service for application interoperability already exists and is operational.**

If SAI **authorization** support is to be added in the future, the following must be true:

1. ✅ **Feature Flag**: Implementation must be behind explicit configuration
2. ✅ **Shadow Mode**: Default to non-enforcing behavior
3. ✅ **Interface Compliance**: Must implement existing parser/evaluator interfaces
4. ✅ **Test Coverage**: Must have comprehensive test suite
5. ⬜ **Specification Stability**: SAI authorization spec must be stable and documented
6. ⬜ **Interoperability**: Multiple implementations must demonstrate compatibility
7. ⬜ **Security Review**: Independent security review must be completed

## Current Implementation Summary

**As of Phase 40 - Status Reconciliation:**

| Component | Status | Notes |
|-----------|--------|-------|
| SAI Service (Application Interoperability) | ✅ **IMPLEMENTED** | Full service with storage, models, flows |
| SAI Authorization Inference | ❌ **DEFERRED** | Not implemented, not needed for current use cases |
| WAC Parser/Evaluator | ✅ **IMPLEMENTED** | Production-ready in shadow mode |
| ACP Parser/Evaluator | ✅ **IMPLEMENTED** | Production-ready in shadow mode |
| CSS Compatibility | ✅ **IMPLEMENTED** | Full reverse-proxy compatibility |

## Migration Path (if SAI Authorization is needed)

**Note: This migration path is for SAI authorization inference, NOT for the existing SAI service which is already implemented.**

If SAI authorization inference is determined to be needed in the future:

1. **Phase 40.1**: Clarify SAI requirements and specification scope
2. **Phase 40.2**: Create SAI parser (shadow mode only)
3. **Phase 40.3**: Create SAI evaluator (shadow mode only)
4. **Phase 40.4**: Add SAI to policy discovery
5. **Phase 40.5**: Compare SAI decisions against WAC/ACP/CSS
6. **Phase 40.6**: Add enforcement mode (after extensive testing)

## Phase 40 Reconciliation Notes

This document was updated as part of **Phase 40: Status Reconciliation** to resolve the following contradiction:

**Before Phase 40:**
- Documentation stated: "SAI support is NOT YET IMPLEMENTED"
- Actual code: Substantial SAI service implementation exists in `internal/sai/`

**After Phase 40:**
- **Clarified**: SAI **Application Interoperability** service is implemented
- **Clarified**: SAI **Authorization Inference** enforcement is deferred
- **Resolution**: Documentation now distinguishes between service implementation and authorization enforcement

This reconciliation ensures that:
1. The SAI service implementation is properly documented
2. The deferral applies only to authorization enforcement, not the entire SAI feature
3. Future work can proceed with accurate understanding of current state

## References

- [Solid Specification](https://solidproject.org/specification)
- [WAC Specification](https://solidproject.org/edn/spec/wac)
- [ACP Specification](https://solidproject.org/edn/spec/acp)
- [Solid Application Interoperability (SAI)](https://solidproject.org/TR/sai-primer-application) - Official SAI specification for application interoperability
- [SAI Discussion](https://github.com/solid/solid-spec/issues) - SAI development discussions

## Related Documentation

- `docs/repository-audit-2026-07-02.md` - Repository audit that identified the SAI documentation contradiction
- `docs/implementation-status.md` - Overall implementation status (updated in Phase 40)
- `docs/phase-40-status-reconciliation.md` - Phase 40 status reconciliation work

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-06-30 | Mistral Vibe | Initial decision document |
| 2026-07-06 | Mistral Vibe | **Phase 40**: Resolved documentation contradiction - SAI service is implemented, SAI authorization enforcement is deferred |

## Document Status

**This document is part of Phase 40: Status Reconciliation and is being actively updated.**

- ✅ SAI service implementation clarified
- ✅ Documentation contradiction resolved
- ⚠️ Final review pending completion of Phase 40

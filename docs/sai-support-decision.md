# SAI Support Decision

This document describes the Solid Authorization Inference (SAI) support decision for the solid-sidecar project, including target semantics, interoperability expectations, and deferral risks.

## Overview

Solid Authorization Inference (SAI) is a proposed authorization mechanism for Solid that aims to provide more expressive and flexible access control than WAC and ACP. This document outlines whether, when, and how SAI support should be implemented in solid-sidecar.

## Current State

As of Phase 9, solid-sidecar supports:
- **WAC (Web Access Control)**: Full parser and evaluator in shadow mode
- **ACP (Access Control Policy)**: Full parser and evaluator in shadow mode
- **CSS Compatibility**: Full reverse-proxy compatibility with Community Solid Server

SAI support is **NOT YET IMPLEMENTED** and remains an explicit decision point.

## Decision: Explicit Deferral with Prepared Boundary

**Decision**: SAI parsing and evaluation is **EXPLICITLY DEFERRED** until the following conditions are met:

1. **Documented Semantics**: SAI semantics must be fully documented in an official Solid specification or W3C draft that this project can reference.
2. **Interoperability Evidence**: At least two independent Solid server implementations must demonstrate interoperable SAI behavior.
3. **Test Fixtures**: A comprehensive set of SAI test fixtures must be available and reviewed by the project maintainers.
4. **Security Review**: SAI security properties must be independently reviewed with no identified vulnerabilities in the inference model.
5. **Shadow-Only First**: Any SAI implementation must start in shadow mode with explicit configuration gates.

## Rationale for Deferral

### 1. Specification Maturity

SAI, as of the time of this writing, does not have a stable, widely-implemented specification. The inference rules and semantics are still under active development in the Solid community. Implementing SAI before specification stabilization risks:

- **Breaking Changes**: Implementation would need significant rewrites as the spec evolves
- **Incompatibility**: Different Solid servers would implement different SAI variants
- **Security Gaps**: Undiscovered edge cases in the inference model could lead to authorization bypasses

### 2. Complexity vs. Value

SAI adds significant complexity to the authorization model:

- **Inference Engine**: Requires a forward-chaining or backward-chaining inference engine
- **Rule Conflict Resolution**: Must define deterministic conflict resolution for competing inferences
- **Performance**: Inference can be computationally expensive, requiring caching and optimization
- **Debugging**: Authorization decisions become harder to explain and debug

The current WAC and ACP implementations cover the vast majority of Solid use cases without the complexity of inference.

### 3. Authorization Completeness

WAC and ACP already provide:
- Direct access grants and denials
- Agent and agent class matching
- Mode-based access control (read, write, append, control)
- Container inheritance
- Public access
- Group membership (via agentClass)

SAI's primary value proposition—rule inference and delegation chains—can be achieved through:
- Explicit policy composition in ACP
- Container-level policies in WAC
- Application-level logic

### 4. Risk Profile

SAI introduces new security risks:

- **Inference Attacks**: Malicious policies could craft inference chains that cause denial of service
- **Rule Interaction**: Complex rule interactions could lead to unintended access grants
- **Debugging Complexity**: Security audits become more difficult with inferred permissions
- **Implementation Bugs**: Any bug in the inference engine could have authorization-wide impact

## Prepared Boundary

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

## Acceptance Criteria for Future Implementation

If SAI support is to be added in the future, the following must be true:

1. ✅ **Feature Flag**: Implementation must be behind explicit configuration
2. ✅ **Shadow Mode**: Default to non-enforcing behavior
3. ✅ **Interface Compliance**: Must implement existing parser/evaluator interfaces
4. ✅ **Test Coverage**: Must have comprehensive test suite
5. ⬜ **Specification Stability**: SAI spec must be stable and documented
6. ⬜ **Interoperability**: Multiple implementations must demonstrate compatibility
7. ⬜ **Security Review**: Independent security review must be completed

## Migration Path

When SAI is ready for implementation:

1. **Phase 9.1**: Create SAI parser (shadow mode only)
2. **Phase 9.2**: Create SAI evaluator (shadow mode only)
3. **Phase 9.3**: Add SAI to policy discovery
4. **Phase 9.4**: Compare SAI decisions against WAC/ACP/CSS
5. **Phase 9.5**: Add enforcement mode (after extensive testing)

## References

- [Solid Specification](https://solidproject.org/specification)
- [WAC Specification](https://solidproject.org/edn/spec/wac)
- [ACP Specification](https://solidproject.org/edn/spec/acp)
- [SAI Discussion](https://github.com/solid/solid-spec/issues) - Note: SAI is not yet standardized

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-06-30 | Mistral Vibe | Initial decision document |

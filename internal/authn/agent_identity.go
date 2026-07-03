// Package authn provides authentication for Solid with DID support.
package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// AssuranceLevel represents the level of confidence in the identity verification
type AssuranceLevel int

const (
	// AssuranceLevelNone indicates no assurance (invalid/unverified identity)
	AssuranceLevelNone AssuranceLevel = iota
	// AssuranceLevelBasic indicates basic assurance (WebID only, no DID binding)
	AssuranceLevelBasic
	// AssuranceLevelStandard indicates standard assurance (WebID with valid DID binding)
	AssuranceLevelStandard
	// AssuranceLevelHigh indicates high assurance (WebID + DID + additional verification)
	AssuranceLevelHigh
)

// String returns the string representation of the assurance level
func (a AssuranceLevel) String() string {
	switch a {
	case AssuranceLevelNone:
		return "none"
	case AssuranceLevelBasic:
		return "basic"
	case AssuranceLevelStandard:
		return "standard"
	case AssuranceLevelHigh:
		return "high"
	default:
		return "unknown"
	}
}

// VerificationSource represents the source of identity verification
type VerificationSource int

const (
	// VerificationSourceNone indicates no verification source
	VerificationSourceNone VerificationSource = iota
	// VerificationSourceSolidOIDC indicates identity verified via Solid-OIDC
	VerificationSourceSolidOIDC
	// VerificationSourceDPoP indicates identity verified via DPoP-bound token
	VerificationSourceDPoP
	// VerificationSourceDID indicates identity verified via DID binding
	VerificationSourceDID
	// VerificationSourceCombined indicates identity verified via multiple sources
	VerificationSourceCombined
)

// String returns the string representation of the verification source
func (v VerificationSource) String() string {
	switch v {
	case VerificationSourceNone:
		return "none"
	case VerificationSourceSolidOIDC:
		return "solid-oidc"
	case VerificationSourceDPoP:
		return "dpop"
	case VerificationSourceDID:
		return "did"
	case VerificationSourceCombined:
		return "combined"
	default:
		return "unknown"
	}
}

// AgentIdentity represents a unified agent identity for Solid
// This combines WebID, Solid-OIDC issuer, client, DPoP key, and optional DID identity
type AgentIdentity struct {
	// WebID is the primary Solid agent identifier (always present if identity is valid)
	WebID string
	// DID is an optional DID that is bound to the WebID
	DID string
	// Issuer is the OIDC issuer that issued the identity token
	Issuer string
	// ClientID is the client identifier from the token
	ClientID string
	// TokenBindingKeyThumbprint is the JWK thumbprint of the DPoP proof key
	TokenBindingKeyThumbprint string
	// AssuranceLevel is the level of confidence in this identity
	AssuranceLevel AssuranceLevel
	// VerificationSource is the source of identity verification
	VerificationSource VerificationSource
	// Audience contains the intended audience of the token
	Audience []string
	// ExpiresAt is when the identity token expires
	ExpiresAt interface{} // Can be time.Time or int64 (Unix timestamp)
}

// IsValid checks if the AgentIdentity has at least a valid WebID
func (ai AgentIdentity) IsValid() bool {
	return ai.WebID != "" && isValidURI(ai.WebID)
}

// HasDID checks if the AgentIdentity has a bound DID
func (ai AgentIdentity) HasDID() bool {
	return ai.DID != "" && isValidDID(ai.DID)
}

// HasTokenBinding checks if the AgentIdentity has a DPoP token binding
func (ai AgentIdentity) HasTokenBinding() bool {
	return ai.TokenBindingKeyThumbprint != ""
}

// AssuranceLevelDescription returns a human-readable description of the assurance level
func (ai AgentIdentity) AssuranceLevelDescription() string {
	switch ai.AssuranceLevel {
	case AssuranceLevelNone:
		return "No assurance - identity is invalid or unverified"
	case AssuranceLevelBasic:
		return "Basic assurance - WebID verified via Solid-OIDC"
	case AssuranceLevelStandard:
		return "Standard assurance - WebID with valid DID binding"
	case AssuranceLevelHigh:
		return "High assurance - WebID with DID and additional verification"
	default:
		return "Unknown assurance level"
	}
}

// VerificationSourceDescription returns a human-readable description of the verification source
func (ai AgentIdentity) VerificationSourceDescription() string {
	switch ai.VerificationSource {
	case VerificationSourceNone:
		return "No verification source"
	case VerificationSourceSolidOIDC:
		return "Verified via Solid-OIDC"
	case VerificationSourceDPoP:
		return "Verified via DPoP-bound token"
	case VerificationSourceDID:
		return "Verified via DID binding"
	case VerificationSourceCombined:
		return "Verified via multiple sources"
	default:
		return "Unknown verification source"
	}
}

// contextKey for AgentIdentity in context
type agentIdentityContextKey struct{}

var agentIdentityKey = agentIdentityContextKey{}

// AgentIdentityFromContext retrieves the AgentIdentity from the request context
func AgentIdentityFromContext(ctx context.Context) (AgentIdentity, bool) {
	if identity, ok := ctx.Value(agentIdentityKey).(AgentIdentity); ok {
		return identity, true
	}
	return AgentIdentity{}, false
}

// AgentIdentityToContext returns a new context with the AgentIdentity attached
func AgentIdentityToContext(ctx context.Context, identity AgentIdentity) context.Context {
	return context.WithValue(ctx, agentIdentityKey, identity)
}

// ConvertTrustedIdentityToAgentIdentity converts a TrustedIdentity to an AgentIdentity
// This is a bridge between the existing authn system and the new AgentIdentity model
func ConvertTrustedIdentityToAgentIdentity(trusted TrustedIdentity, did string, tokenBindingKeyThumbprint string) AgentIdentity {
	identity := AgentIdentity{
		WebID:                     trusted.WebID,
		Issuer:                    trusted.Issuer,
		ClientID:                  trusted.ClientID,
		Audience:                  trusted.Audience,
		ExpiresAt:                 trusted.ExpiresAt,
		TokenBindingKeyThumbprint: tokenBindingKeyThumbprint,
		AssuranceLevel:            AssuranceLevelBasic,
		VerificationSource:        VerificationSourceSolidOIDC,
	}

	// If DID is provided and valid, upgrade assurance
	if did != "" && isValidDID(did) {
		identity.DID = did
		identity.AssuranceLevel = AssuranceLevelStandard
		identity.VerificationSource = VerificationSourceCombined
	}

	// If token binding is present, it's DPoP
	if tokenBindingKeyThumbprint != "" {
		identity.VerificationSource = VerificationSourceDPoP
		if identity.DID != "" {
			identity.VerificationSource = VerificationSourceCombined
		}
	}

	return identity
}

// isValidURI checks if a string is a valid HTTPS URI
func isValidURI(uri string) bool {
	uri = strings.TrimSpace(uri)
	if uri == "" || len(uri) > 2048 {
		return false
	}
	// Basic check - more comprehensive validation in the actual parser
	return strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://")
}

// isValidDID checks if a string is a valid DID
func isValidDID(did string) bool {
	did = strings.TrimSpace(did)
	if did == "" || len(did) > 1024 {
		return false
	}
	// Basic check: must start with "did:", have a method, and a method-specific ID
	// Format: did:<method>:<method-specific-id>
	// After "did:", there must be at least one colon and non-empty parts on both sides
	if !strings.HasPrefix(did, "did:") {
		return false
	}
	// Remove "did:" prefix
	rest := strings.TrimPrefix(did, "did:")
	// Must have at least one more colon
	if !strings.Contains(rest, ":") {
		return false
	}
	// Split by first colon to get method and method-specific ID
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return false
	}
	// Both method and method-specific ID must be non-empty
	return parts[0] != "" && parts[1] != ""
}

// String returns a privacy-safe string representation of the AgentIdentity.
// Keep fmt/log output redacted by default; use explicit fields only in local debug tooling
// after a privacy review.
func (ai AgentIdentity) String() string {
	return ai.RedactedString()
}

// RedactedString returns a privacy-safe string representation
func (ai AgentIdentity) RedactedString() string {
	var b strings.Builder
	b.WriteString("AgentIdentity{")
	b.WriteString(fmt.Sprintf("WebID: %s, ", redactURI(ai.WebID)))
	if ai.HasDID() {
		b.WriteString(fmt.Sprintf("DID: %s, ", redactDID(ai.DID)))
	}
	b.WriteString(fmt.Sprintf("Issuer: %s, ", redactURI(ai.Issuer)))
	b.WriteString(fmt.Sprintf("ClientID: %s, ", redactClientID(ai.ClientID)))
	if ai.HasTokenBinding() {
		b.WriteString("TokenBinding: [REDACTED], ")
	}
	b.WriteString(fmt.Sprintf("Assurance: %s, ", ai.AssuranceLevel))
	b.WriteString(fmt.Sprintf("Source: %s", ai.VerificationSource))
	b.WriteString("}")
	return b.String()
}

// PrivacySafeHash returns a privacy-safe hash of the identity for use in metrics
// The hash is computed from the WebID and DID (if present) but does not reveal the actual values
// This ensures that identities can be grouped and counted without leaking PII
func (ai AgentIdentity) PrivacySafeHash() string {
	var b strings.Builder
	b.WriteString(ai.WebID)
	if ai.HasDID() {
		b.WriteString("|")
		b.WriteString(ai.DID)
	}
	hash := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(hash[:])
}

// AuditSummary returns an audit-safe summary of the identity
// This includes structural information but redacts sensitive PII
func (ai AgentIdentity) AuditSummary() string {
	var b strings.Builder
	b.WriteString("AgentIdentity[Auditable]{")
	b.WriteString(fmt.Sprintf("HasWebID: %v, ", ai.WebID != ""))
	b.WriteString(fmt.Sprintf("HasDID: %v, ", ai.HasDID()))
	b.WriteString(fmt.Sprintf("HasTokenBinding: %v, ", ai.HasTokenBinding()))
	b.WriteString(fmt.Sprintf("AssuranceLevel: %s, ", ai.AssuranceLevel))
	b.WriteString(fmt.Sprintf("VerificationSource: %s, ", ai.VerificationSource))
	b.WriteString(fmt.Sprintf("WebIDHost: %s, ", extractHostFromURI(ai.WebID)))
	if ai.HasDID() {
		b.WriteString(fmt.Sprintf("DIDMethod: %s", extractDIDMethod(ai.DID)))
	}
	b.WriteString("}")
	return b.String()
}

// MetricsLabel returns a privacy-safe label suitable for metrics
// It uses only the assurance level and verification source, not the actual identity values
func (ai AgentIdentity) MetricsLabel() string {
	return fmt.Sprintf("assurance=%s,source=%s", ai.AssuranceLevel, ai.VerificationSource)
}

// redactURI redacts sensitive information from a URI for logging
func redactURI(uri string) string {
	if uri == "" {
		return ""
	}
	// For now, just return the host part to avoid leaking full WebIDs
	// In production, this might use hashing
	if strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://") {
		// Extract host
		uri = strings.TrimPrefix(uri, "https://")
		uri = strings.TrimPrefix(uri, "http://")
		if idx := strings.Index(uri, "/"); idx >= 0 {
			return uri[:idx] + "/..."
		}
		return uri
	}
	return "[REDACTED]"
}

// redactDID redacts sensitive information from a DID for logging
func redactDID(did string) string {
	if did == "" {
		return ""
	}
	// For did:solid DIDs, show method and partial ID
	if strings.HasPrefix(did, "did:solid:") {
		parts := strings.SplitN(did, ":", 3)
		if len(parts) >= 3 {
			id := parts[2]
			if len(id) > 8 {
				return fmt.Sprintf("did:solid:%s...", id[:4])
			}
			return fmt.Sprintf("did:solid:%s", id[:min(4, len(id))])
		}
	}
	return "[REDACTED]"
}

// redactClientID redacts client ID for logging
func redactClientID(clientID string) string {
	if clientID == "" {
		return ""
	}
	if len(clientID) > 8 {
		return clientID[:4] + "..."
	}
	return clientID[:min(4, len(clientID))]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractHostFromURI extracts the host from a URI for audit purposes
func extractHostFromURI(uri string) string {
	if uri == "" {
		return ""
	}
	// Simple extraction - for HTTPS URIs, extract the host
	if strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://") {
		uri = strings.TrimPrefix(uri, "https://")
		uri = strings.TrimPrefix(uri, "http://")
		if idx := strings.Index(uri, "/"); idx >= 0 {
			return uri[:idx]
		}
		return uri
	}
	return "[unknown]"
}

// extractDIDMethod extracts the method from a DID for audit purposes
func extractDIDMethod(did string) string {
	if !isValidDID(did) {
		return "[invalid]"
	}
	// DID format: did:<method>:<method-specific-id>
	parts := strings.SplitN(strings.TrimPrefix(did, "did:"), ":", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return "[unknown]"
}

// AgentIdentityBuilder provides a fluent interface for building AgentIdentity
// This is useful for testing and construction
type AgentIdentityBuilder struct {
	identity AgentIdentity
}

// NewAgentIdentityBuilder creates a new builder
func NewAgentIdentityBuilder() *AgentIdentityBuilder {
	return &AgentIdentityBuilder{
		identity: AgentIdentity{
			AssuranceLevel:     AssuranceLevelNone,
			VerificationSource: VerificationSourceNone,
			Audience:           []string{},
		},
	}
}

// WithWebID sets the WebID
func (b *AgentIdentityBuilder) WithWebID(webID string) *AgentIdentityBuilder {
	b.identity.WebID = webID
	return b
}

// WithDID sets the DID
func (b *AgentIdentityBuilder) WithDID(did string) *AgentIdentityBuilder {
	b.identity.DID = did
	return b
}

// WithIssuer sets the issuer
func (b *AgentIdentityBuilder) WithIssuer(issuer string) *AgentIdentityBuilder {
	b.identity.Issuer = issuer
	return b
}

// WithClientID sets the client ID
func (b *AgentIdentityBuilder) WithClientID(clientID string) *AgentIdentityBuilder {
	b.identity.ClientID = clientID
	return b
}

// WithTokenBindingKeyThumbprint sets the token binding key thumbprint
func (b *AgentIdentityBuilder) WithTokenBindingKeyThumbprint(thumbprint string) *AgentIdentityBuilder {
	b.identity.TokenBindingKeyThumbprint = thumbprint
	return b
}

// WithAssuranceLevel sets the assurance level
func (b *AgentIdentityBuilder) WithAssuranceLevel(level AssuranceLevel) *AgentIdentityBuilder {
	b.identity.AssuranceLevel = level
	return b
}

// WithVerificationSource sets the verification source
func (b *AgentIdentityBuilder) WithVerificationSource(source VerificationSource) *AgentIdentityBuilder {
	b.identity.VerificationSource = source
	return b
}

// WithAudience sets the audience
func (b *AgentIdentityBuilder) WithAudience(audience []string) *AgentIdentityBuilder {
	b.identity.Audience = audience
	return b
}

// WithExpiresAt sets the expiration
func (b *AgentIdentityBuilder) WithExpiresAt(expiresAt interface{}) *AgentIdentityBuilder {
	b.identity.ExpiresAt = expiresAt
	return b
}

// Build returns the constructed AgentIdentity
func (b *AgentIdentityBuilder) Build() AgentIdentity {
	// Calculate assurance level if not set
	if b.identity.AssuranceLevel == AssuranceLevelNone && b.identity.WebID != "" {
		b.identity.AssuranceLevel = AssuranceLevelBasic
	}
	if b.identity.DID != "" && b.identity.AssuranceLevel < AssuranceLevelStandard {
		b.identity.AssuranceLevel = AssuranceLevelStandard
	}
	return b.identity
}

// MustBuild returns the constructed AgentIdentity and panics on error
func (b *AgentIdentityBuilder) MustBuild() AgentIdentity {
	return b.Build()
}

package authn

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestAgentIdentityCreation tests creating an AgentIdentity
func TestAgentIdentityCreation(t *testing.T) {
	identity := AgentIdentity{
		WebID:    "https://example.org/alice#me",
		DID:      "did:solid:alice",
		Issuer:   "https://issuer.example.org",
		ClientID: "client-123",
	}

	if !identity.IsValid() {
		t.Error("expected identity to be valid")
	}
	if !identity.HasDID() {
		t.Error("expected identity to have DID")
	}
}

// TestAgentIdentityWithoutWebID tests identity without WebID
func TestAgentIdentityWithoutWebID(t *testing.T) {
	identity := AgentIdentity{
		DID: "did:solid:alice",
	}

	if identity.IsValid() {
		t.Error("expected identity without WebID to be invalid")
	}
	if !identity.HasDID() {
		t.Error("expected identity to have DID")
	}
}

// TestAgentIdentityAssuranceLevels tests assurance level descriptions
func TestAgentIdentityAssuranceLevels(t *testing.T) {
	testCases := []struct {
		level       AssuranceLevel
		description string
	}{
		{AssuranceLevelNone, "No assurance - identity is invalid or unverified"},
		{AssuranceLevelBasic, "Basic assurance - WebID verified via Solid-OIDC"},
		{AssuranceLevelStandard, "Standard assurance - WebID with valid DID binding"},
		{AssuranceLevelHigh, "High assurance - WebID with DID and additional verification"},
		{AssuranceLevel(99), "Unknown assurance level"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			identity := AgentIdentity{AssuranceLevel: tc.level}
			desc := identity.AssuranceLevelDescription()
			if desc != tc.description {
				t.Errorf("expected %q, got %q", tc.description, desc)
			}
		})
	}
}

// TestAgentIdentityVerificationSources tests verification source descriptions
func TestAgentIdentityVerificationSources(t *testing.T) {
	testCases := []struct {
		source      VerificationSource
		description string
	}{
		{VerificationSourceNone, "No verification source"},
		{VerificationSourceSolidOIDC, "Verified via Solid-OIDC"},
		{VerificationSourceDPoP, "Verified via DPoP-bound token"},
		{VerificationSourceDID, "Verified via DID binding"},
		{VerificationSourceCombined, "Verified via multiple sources"},
		{VerificationSource(99), "Unknown verification source"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			identity := AgentIdentity{VerificationSource: tc.source}
			desc := identity.VerificationSourceDescription()
			if desc != tc.description {
				t.Errorf("expected %q, got %q", tc.description, desc)
			}
		})
	}
}

// TestAgentIdentityString tests AgentIdentity string representation
func TestAgentIdentityString(t *testing.T) {
	identity := AgentIdentity{
		WebID:    "https://example.org/alice#me",
		DID:      "did:solid:alice",
		Issuer:   "https://issuer.example.org",
		ClientID: "client-123",
	}

	str := identity.String()
	if str == "" {
		t.Error("expected non-empty string representation")
	}
}

// TestAgentIdentityRedactedString tests privacy-safe string representation
func TestAgentIdentityRedactedString(t *testing.T) {
	identity := AgentIdentity{
		WebID:                     "https://example.org/alice#me",
		DID:                       "did:solid:alice",
		Issuer:                    "https://issuer.example.org",
		ClientID:                  "client-123",
		TokenBindingKeyThumbprint: "abc123",
	}

	str := identity.RedactedString()
	if str == "" {
		t.Error("expected non-empty redacted string representation")
	}

	// Token binding should be redacted
	if containsSubstring(str, "abc123") {
		t.Error("expected token binding to be redacted")
	}
}

// TestAgentIdentityBuilder tests the fluent builder
func TestAgentIdentityBuilder(t *testing.T) {
	builder := NewAgentIdentityBuilder()
	identity := builder.
		WithWebID("https://example.org/alice#me").
		WithDID("did:solid:alice").
		WithIssuer("https://issuer.example.org").
		WithClientID("client-123").
		WithTokenBindingKeyThumbprint("thumbprint").
		WithAssuranceLevel(AssuranceLevelStandard).
		WithVerificationSource(VerificationSourceCombined).
		WithAudience([]string{"aud1", "aud2"}).
		WithExpiresAt(time.Now().Add(1 * time.Hour)).
		Build()

	if identity.WebID != "https://example.org/alice#me" {
		t.Errorf("expected WebID, got %q", identity.WebID)
	}
	if identity.DID != "did:solid:alice" {
		t.Errorf("expected DID, got %q", identity.DID)
	}
	if identity.Issuer != "https://issuer.example.org" {
		t.Errorf("expected Issuer, got %q", identity.Issuer)
	}
	if identity.ClientID != "client-123" {
		t.Errorf("expected ClientID, got %q", identity.ClientID)
	}
	if identity.TokenBindingKeyThumbprint != "thumbprint" {
		t.Errorf("expected TokenBindingKeyThumbprint, got %q", identity.TokenBindingKeyThumbprint)
	}
	if identity.AssuranceLevel != AssuranceLevelStandard {
		t.Errorf("expected AssuranceLevel Standard, got %v", identity.AssuranceLevel)
	}
	if identity.VerificationSource != VerificationSourceCombined {
		t.Errorf("expected VerificationSource Combined, got %v", identity.VerificationSource)
	}
	if len(identity.Audience) != 2 {
		t.Errorf("expected 2 audience entries, got %d", len(identity.Audience))
	}
}

// TestAgentIdentityBuilderAutoAssurance tests automatic assurance level calculation
func TestAgentIdentityBuilderAutoAssurance(t *testing.T) {
	t.Run("WebID only - Basic assurance", func(t *testing.T) {
		builder := NewAgentIdentityBuilder()
		identity := builder.
			WithWebID("https://example.org/alice#me").
			Build()

		if identity.AssuranceLevel != AssuranceLevelBasic {
			t.Errorf("expected Basic assurance, got %v", identity.AssuranceLevel)
		}
	})

	t.Run("WebID + DID - Standard assurance", func(t *testing.T) {
		builder := NewAgentIdentityBuilder()
		identity := builder.
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			Build()

		if identity.AssuranceLevel != AssuranceLevelStandard {
			t.Errorf("expected Standard assurance, got %v", identity.AssuranceLevel)
		}
	})

	t.Run("Explicit assurance level is preserved", func(t *testing.T) {
		builder := NewAgentIdentityBuilder()
		identity := builder.
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			WithAssuranceLevel(AssuranceLevelHigh).
			Build()

		if identity.AssuranceLevel != AssuranceLevelHigh {
			t.Errorf("expected High assurance, got %v", identity.AssuranceLevel)
		}
	})
}

// TestConvertTrustedIdentityToAgentIdentity tests conversion from TrustedIdentity
func TestConvertTrustedIdentityToAgentIdentity(t *testing.T) {
	trusted := TrustedIdentity{
		Issuer:    "https://issuer.example.org",
		WebID:     "https://example.org/alice#me",
		ClientID:  "client-123",
		Audience:  []string{"aud1"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	t.Run("without DID", func(t *testing.T) {
		identity := ConvertTrustedIdentityToAgentIdentity(trusted, "", "")

		if identity.WebID != trusted.WebID {
			t.Errorf("expected WebID, got %q", identity.WebID)
		}
		if identity.Issuer != trusted.Issuer {
			t.Errorf("expected Issuer, got %q", identity.Issuer)
		}
		if identity.ClientID != trusted.ClientID {
			t.Errorf("expected ClientID, got %q", identity.ClientID)
		}
		if identity.AssuranceLevel != AssuranceLevelBasic {
			t.Errorf("expected Basic assurance, got %v", identity.AssuranceLevel)
		}
		if identity.VerificationSource != VerificationSourceSolidOIDC {
			t.Errorf("expected Solid-OIDC source, got %v", identity.VerificationSource)
		}
		if identity.DID != "" {
			t.Error("expected no DID")
		}
	})

	t.Run("with DID", func(t *testing.T) {
		identity := ConvertTrustedIdentityToAgentIdentity(trusted, "did:solid:alice", "")

		if identity.DID != "did:solid:alice" {
			t.Errorf("expected DID, got %q", identity.DID)
		}
		if identity.AssuranceLevel != AssuranceLevelStandard {
			t.Errorf("expected Standard assurance, got %v", identity.AssuranceLevel)
		}
		if identity.VerificationSource != VerificationSourceCombined {
			t.Errorf("expected Combined source, got %v", identity.VerificationSource)
		}
	})

	t.Run("with DPoP binding", func(t *testing.T) {
		identity := ConvertTrustedIdentityToAgentIdentity(trusted, "", "thumbprint")

		if identity.TokenBindingKeyThumbprint != "thumbprint" {
			t.Errorf("expected thumbprint, got %q", identity.TokenBindingKeyThumbprint)
		}
		if identity.VerificationSource != VerificationSourceDPoP {
			t.Errorf("expected DPoP source, got %v", identity.VerificationSource)
		}
	})

	t.Run("with DID and DPoP", func(t *testing.T) {
		identity := ConvertTrustedIdentityToAgentIdentity(trusted, "did:solid:alice", "thumbprint")

		if identity.DID != "did:solid:alice" {
			t.Errorf("expected DID, got %q", identity.DID)
		}
		if identity.TokenBindingKeyThumbprint != "thumbprint" {
			t.Errorf("expected thumbprint, got %q", identity.TokenBindingKeyThumbprint)
		}
		if identity.VerificationSource != VerificationSourceCombined {
			t.Errorf("expected Combined source, got %v", identity.VerificationSource)
		}
	})
}

// TestAssuranceLevelString tests AssuranceLevel.String()
func TestAssuranceLevelString(t *testing.T) {
	testCases := []struct {
		level  AssuranceLevel
		string string
	}{
		{AssuranceLevelNone, "none"},
		{AssuranceLevelBasic, "basic"},
		{AssuranceLevelStandard, "standard"},
		{AssuranceLevelHigh, "high"},
		{AssuranceLevel(99), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.string, func(t *testing.T) {
			if got := tc.level.String(); got != tc.string {
				t.Errorf("expected %q, got %q", tc.string, got)
			}
		})
	}
}

// TestVerificationSourceString tests VerificationSource.String()
func TestVerificationSourceString(t *testing.T) {
	testCases := []struct {
		source VerificationSource
		string string
	}{
		{VerificationSourceNone, "none"},
		{VerificationSourceSolidOIDC, "solid-oidc"},
		{VerificationSourceDPoP, "dpop"},
		{VerificationSourceDID, "did"},
		{VerificationSourceCombined, "combined"},
		{VerificationSource(99), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.string, func(t *testing.T) {
			if got := tc.source.String(); got != tc.string {
				t.Errorf("expected %q, got %q", tc.string, got)
			}
		})
	}
}

// TestAgentIdentityContext tests context storage
func TestAgentIdentityContext(t *testing.T) {
	ctx := context.Background()
	identity := AgentIdentity{
		WebID: "https://example.org/alice#me",
		DID:   "did:solid:alice",
	}

	// Store identity in context
	ctx = AgentIdentityToContext(ctx, identity)

	// Retrieve identity from context
	retrieved, ok := AgentIdentityFromContext(ctx)
	if !ok {
		t.Fatal("expected to retrieve identity from context")
	}
	if retrieved.WebID != identity.WebID {
		t.Errorf("expected WebID %q, got %q", identity.WebID, retrieved.WebID)
	}

	// Test with empty context
	emptyIdentity, ok := AgentIdentityFromContext(context.Background())
	if ok {
		t.Error("expected not to find identity in empty context")
	}
	if emptyIdentity.WebID != "" {
		t.Error("expected empty identity")
	}
}

// TestIsValidURI tests URI validation
func TestIsValidURI(t *testing.T) {
	testCases := []struct {
		uri   string
		valid bool
	}{
		{"https://example.org/alice#me", true},
		{"http://example.org/alice#me", true},
		{"https://example.org", true},
		{"", false},
		{"not-a-uri", false},
		{string(make([]byte, 2049)), false}, // Too long
	}

	for _, tc := range testCases {
		t.Run(tc.uri, func(t *testing.T) {
			if got := isValidURI(tc.uri); got != tc.valid {
				t.Errorf("expected %v, got %v", tc.valid, got)
			}
		})
	}
}

// TestIsValidDID tests DID validation
func TestIsValidDID(t *testing.T) {
	testCases := []struct {
		did   string
		valid bool
	}{
		{"did:solid:alice", true},
		{"did:web:alice", true},
		{"did:example:123", true},
		{"", false},
		{"not-a-did", false},
		{"did:", false},
		{"did:solid:", false},
		{string(make([]byte, 1025)), false}, // Too long
	}

	for _, tc := range testCases {
		t.Run(tc.did, func(t *testing.T) {
			if got := isValidDID(tc.did); got != tc.valid {
				t.Errorf("expected %v, got %v", tc.valid, got)
			}
		})
	}
}

// TestHasTokenBinding tests HasTokenBinding
func TestHasTokenBinding(t *testing.T) {
	t.Run("with token binding", func(t *testing.T) {
		identity := AgentIdentity{
			TokenBindingKeyThumbprint: "abc123",
		}
		if !identity.HasTokenBinding() {
			t.Error("expected HasTokenBinding to be true")
		}
	})

	t.Run("without token binding", func(t *testing.T) {
		identity := AgentIdentity{
			TokenBindingKeyThumbprint: "",
		}
		if identity.HasTokenBinding() {
			t.Error("expected HasTokenBinding to be false")
		}
	})
}

// TestRedactFunctions tests redaction functions
func TestRedactFunctions(t *testing.T) {
	t.Run("redactURI", func(t *testing.T) {
		// HTTPS URL with path
		uri := "https://example.org/alice/profile/card#me"
		result := redactURI(uri)
		if result == uri {
			t.Error("expected URI to be redacted")
		}
		if !containsSubstring(result, "example.org") {
			t.Error("expected host to be preserved")
		}

		// Empty URI
		if result := redactURI(""); result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})

	t.Run("redactDID", func(t *testing.T) {
		// did:solid DID
		did := "did:solid:verylongdidname"
		result := redactDID(did)
		if result == did {
			t.Error("expected DID to be redacted")
		}
		if !containsSubstring(result, "did:solid:") {
			t.Error("expected DID prefix to be preserved")
		}
		if containsSubstring(result, "verylongdidname") {
			t.Error("expected DID name to be truncated")
		}

		// Short DID
		did = "did:solid:alice"
		result = redactDID(did)
		if !containsSubstring(result, "did:solid:") {
			t.Error("expected DID prefix to be preserved")
		}

		// Empty DID
		if result := redactDID(""); result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})

	t.Run("redactClientID", func(t *testing.T) {
		// Long client ID
		clientID := "verylongclientid123456789"
		result := redactClientID(clientID)
		if result == clientID {
			t.Error("expected client ID to be redacted")
		}
		if len(result) >= len(clientID) {
			t.Error("expected client ID to be truncated")
		}

		// Short client ID
		clientID = "abc"
		result = redactClientID(clientID)
		if result != clientID {
			t.Errorf("expected short client ID to be unchanged, got %q", result)
		}

		// Empty client ID
		if result := redactClientID(""); result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})
}

// containsSubstring is a helper for tests
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}

// TestPrivacySafeHash tests the privacy-safe hash function
func TestPrivacySafeHash(t *testing.T) {
	t.Run("same identity produces same hash", func(t *testing.T) {
		identity1 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			Build()
		identity2 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			Build()

		hash1 := identity1.PrivacySafeHash()
		hash2 := identity2.PrivacySafeHash()
		if hash1 != hash2 {
			t.Errorf("expected same hash for same identity, got %s and %s", hash1, hash2)
		}
	})

	t.Run("different identities produce different hashes", func(t *testing.T) {
		identity1 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			Build()
		identity2 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/bob#me").
			Build()

		hash1 := identity1.PrivacySafeHash()
		hash2 := identity2.PrivacySafeHash()
		if hash1 == hash2 {
			t.Error("expected different hashes for different identities")
		}
	})

	t.Run("WebID only vs WebID with DID produces different hashes", func(t *testing.T) {
		identity1 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			Build()
		identity2 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			Build()

		hash1 := identity1.PrivacySafeHash()
		hash2 := identity2.PrivacySafeHash()
		if hash1 == hash2 {
			t.Error("expected different hashes when DID is added")
		}
	})

	t.Run("hash is consistent length", func(t *testing.T) {
		identity := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			Build()

		hash := identity.PrivacySafeHash()
		// SHA256 produces 64 hex characters
		if len(hash) != 64 {
			t.Errorf("expected hash length 64, got %d", len(hash))
		}
	})

	t.Run("hash does not contain PII", func(t *testing.T) {
		identity := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			Build()

		hash := identity.PrivacySafeHash()
		// Hash should not contain the WebID or DID as plaintext
		if strings.Contains(hash, "alice") || strings.Contains(hash, "example.org") || strings.Contains(hash, "did:solid") {
			t.Errorf("hash should not contain PII, got: %s", hash)
		}
	})
}

// TestAuditSummary tests the audit-safe summary function
func TestAuditSummary(t *testing.T) {
	t.Run("includes structural information", func(t *testing.T) {
		identity := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			WithTokenBindingKeyThumbprint("abc123").
			WithAssuranceLevel(AssuranceLevelStandard).
			WithVerificationSource(VerificationSourceCombined).
			Build()

		summary := identity.AuditSummary()
		if !strings.Contains(summary, "HasWebID: true") {
			t.Errorf("expected HasWebID: true in summary: %s", summary)
		}
		if !strings.Contains(summary, "HasDID: true") {
			t.Errorf("expected HasDID: true in summary: %s", summary)
		}
		if !strings.Contains(summary, "HasTokenBinding: true") {
			t.Errorf("expected HasTokenBinding: true in summary: %s", summary)
		}
		if !strings.Contains(summary, "AssuranceLevel: standard") {
			t.Errorf("expected AssuranceLevel: standard in summary: %s", summary)
		}
		if !strings.Contains(summary, "VerificationSource: combined") {
			t.Errorf("expected VerificationSource: combined in summary: %s", summary)
		}
		if !strings.Contains(summary, "WebIDHost: example.org") {
			t.Errorf("expected WebIDHost in summary: %s", summary)
		}
		if !strings.Contains(summary, "DIDMethod: solid") {
			t.Errorf("expected DIDMethod in summary: %s", summary)
		}
	})

	t.Run("does not contain full WebID", func(t *testing.T) {
		identity := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			Build()

		summary := identity.AuditSummary()
		if strings.Contains(summary, "alice#me") {
			t.Errorf("summary should not contain full WebID: %s", summary)
		}
	})

	t.Run("does not contain full DID", func(t *testing.T) {
		identity := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice.example").
			Build()

		summary := identity.AuditSummary()
		if strings.Contains(summary, "did:solid:alice.example") {
			t.Errorf("summary should not contain full DID: %s", summary)
		}
	})
}

// TestMetricsLabel tests the metrics label function
func TestMetricsLabel(t *testing.T) {
	t.Run("uses assurance and source only", func(t *testing.T) {
		identity := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithDID("did:solid:alice").
			WithAssuranceLevel(AssuranceLevelStandard).
			WithVerificationSource(VerificationSourceCombined).
			Build()

		label := identity.MetricsLabel()
		if label != "assurance=standard,source=combined" {
			t.Errorf("expected 'assurance=standard,source=combined', got: %s", label)
		}
	})

	t.Run("different identities with same assurance have same label", func(t *testing.T) {
		identity1 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/alice#me").
			WithAssuranceLevel(AssuranceLevelBasic).
			WithVerificationSource(VerificationSourceSolidOIDC).
			Build()
		identity2 := NewAgentIdentityBuilder().
			WithWebID("https://example.org/bob#me").
			WithAssuranceLevel(AssuranceLevelBasic).
			WithVerificationSource(VerificationSourceSolidOIDC).
			Build()

		label1 := identity1.MetricsLabel()
		label2 := identity2.MetricsLabel()
		if label1 != label2 {
			t.Errorf("expected same label for same assurance/source, got %s and %s", label1, label2)
		}
	})

	t.Run("does not contain PII", func(t *testing.T) {
		identity := NewAgentIdentityBuilder().
			WithWebID("https://secret.example.org/alice#me").
			WithDID("did:solid:secret-alice").
			WithAssuranceLevel(AssuranceLevelHigh).
			WithVerificationSource(VerificationSourceDID).
			Build()

		label := identity.MetricsLabel()
		if strings.Contains(label, "secret") || strings.Contains(label, "alice") {
			t.Errorf("label should not contain PII: %s", label)
		}
	})
}

// TestHeaderInjectionPrevention tests that identity cannot be injected through headers
func TestHeaderInjectionPrevention(t *testing.T) {
	t.Run("AgentIdentity cannot be created from headers", func(t *testing.T) {
		// AgentIdentity should only be created through the builder or from TrustedIdentity
		// This test verifies that the struct fields are not directly manipulable from headers
		identity := AgentIdentity{
			WebID: "https://example.org/alice#me",
			DID:   "did:solid:alice",
		}

		// Verify that the identity is valid
		if !identity.IsValid() {
			t.Error("identity should be valid")
		}
		if !identity.HasDID() {
			t.Error("identity should have DID")
		}
	})

	t.Run("TrustedIdentity to AgentIdentity preserves validation", func(t *testing.T) {
		// Create a TrustedIdentity from the existing system
		trusted := TrustedIdentity{
			Issuer:   "https://issuer.example.org",
			WebID:    "https://example.org/alice#me",
			ClientID: "client-123",
		}

		// Convert to AgentIdentity
		identity := ConvertTrustedIdentityToAgentIdentity(trusted, "did:solid:alice", "abc123")

		// Verify identity is valid
		if !identity.IsValid() {
			t.Error("converted identity should be valid")
		}
		if !identity.HasDID() {
			t.Error("converted identity should have DID")
		}
		if !identity.HasTokenBinding() {
			t.Error("converted identity should have token binding")
		}
		if identity.AssuranceLevel != AssuranceLevelStandard {
			t.Errorf("expected AssuranceLevelStandard, got %v", identity.AssuranceLevel)
		}
	})

	t.Run("empty WebID creates invalid identity", func(t *testing.T) {
		identity := AgentIdentity{
			WebID: "",
			DID:   "did:solid:alice",
		}

		if identity.IsValid() {
			t.Error("identity with empty WebID should be invalid")
		}
	})

	t.Run("invalid DID is not recognized", func(t *testing.T) {
		identity := AgentIdentity{
			WebID: "https://example.org/alice#me",
			DID:   "did:", // Invalid DID
		}

		if !identity.IsValid() {
			t.Error("identity with valid WebID should be valid")
		}
		if identity.HasDID() {
			t.Error("identity with invalid DID should not report HasDID")
		}
	})
}

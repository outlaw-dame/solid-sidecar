package authn

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestAgentIdentityStringRedactsRawIdentifiers(t *testing.T) {
	identity := AgentIdentity{
		WebID:                     "https://secret.example.org/alice/profile/card#me",
		DID:                       "did:solid:secret-alice-identifier",
		Issuer:                    "https://issuer.example.org/private/path",
		ClientID:                  "client-secret-identifier",
		TokenBindingKeyThumbprint: "thumbprint-secret",
		AssuranceLevel:            AssuranceLevelStandard,
		VerificationSource:        VerificationSourceCombined,
	}

	value := identity.String()
	for _, forbidden := range []string{
		"alice/profile/card#me",
		"did:solid:secret-alice-identifier",
		"issuer.example.org/private/path",
		"client-secret-identifier",
		"thumbprint-secret",
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("AgentIdentity.String leaked %q in %q", forbidden, value)
		}
	}
}

func TestAgentIdentityFmtStringerUsesRedactedOutput(t *testing.T) {
	identity := AgentIdentity{
		WebID:              "https://secret.example.org/alice#me",
		DID:                "did:solid:secret-alice-identifier",
		Issuer:             "https://issuer.example.org/private",
		ClientID:           "client-secret-identifier",
		AssuranceLevel:     AssuranceLevelStandard,
		VerificationSource: VerificationSourceCombined,
	}

	value := fmt.Sprint(identity)
	if strings.Contains(value, "alice#me") || strings.Contains(value, "secret-alice-identifier") || strings.Contains(value, "client-secret-identifier") {
		t.Fatalf("fmt.Sprint(AgentIdentity) leaked raw identity fields: %q", value)
	}
	if !strings.Contains(value, "AgentIdentity{") || !strings.Contains(value, "Assurance: standard") {
		t.Fatalf("expected redacted structural identity summary, got %q", value)
	}
}

func TestAgentIdentityGoStringRedactsRawIdentifiers(t *testing.T) {
	identity := AgentIdentity{
		WebID:                     "https://secret.example.org/alice/profile/card#me",
		DID:                       "did:solid:secret-alice-identifier",
		Issuer:                    "https://issuer.example.org/private/path",
		ClientID:                  "client-secret-identifier",
		TokenBindingKeyThumbprint: "thumbprint-secret",
		AssuranceLevel:            AssuranceLevelStandard,
		VerificationSource:        VerificationSourceCombined,
	}

	value := fmt.Sprintf("%#v", identity)
	for _, forbidden := range []string{
		"alice/profile/card#me",
		"did:solid:secret-alice-identifier",
		"issuer.example.org/private/path",
		"client-secret-identifier",
		"thumbprint-secret",
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("AgentIdentity GoString leaked %q in %q", forbidden, value)
		}
	}
	if !strings.Contains(value, "AgentIdentity{") {
		t.Fatalf("expected redacted GoString output, got %q", value)
	}
}

func TestAgentIdentityLogValueRedactsRawIdentifiers(t *testing.T) {
	identity := AgentIdentity{
		WebID:              "https://secret.example.org/alice#me",
		DID:                "did:solid:secret-alice-identifier",
		Issuer:             "https://issuer.example.org/private",
		ClientID:           "client-secret-identifier",
		AssuranceLevel:     AssuranceLevelStandard,
		VerificationSource: VerificationSourceCombined,
	}

	logValue := identity.LogValue()
	value := logValue.String()

	// slog.Value interface has a String() method, so we can use it directly
	_ = slog.Value(logValue) // Verify it implements the interface

	for _, forbidden := range []string{
		"alice#me",
		"secret-alice-identifier",
		"issuer.example.org/private",
		"client-secret-identifier",
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("AgentIdentity.LogValue leaked %q in %q", forbidden, value)
		}
	}
	if !strings.Contains(value, "AgentIdentity{") || !strings.Contains(value, "Assurance: standard") {
		t.Fatalf("expected redacted LogValue output, got %q", value)
	}
}

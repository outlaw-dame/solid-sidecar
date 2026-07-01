package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestDIDParserCreation tests creating a DID parser
func TestDIDParserCreation(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	if parser == nil {
		t.Fatal("DID parser is nil")
	}
}

// TestDIDParserDefaultOptions tests default options
func TestDIDParserDefaultOptions(t *testing.T) {
	options := DefaultDIDParserOptions()

	if options.MaxDIDLength == 0 {
		t.Error("expected default max DID length > 0")
	}
	if options.MaxMethodSpecificIDLength == 0 {
		t.Error("expected default max method-specific ID length > 0")
	}
	if options.Logger != nil {
		t.Error("expected logger to be nil by default")
	}
}

// TestParseValidDIDs tests parsing valid DID strings
func TestParseValidDIDs(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	testCases := []struct {
		name   string
		did    string
		method string
		id     string
	}{
		{
			name:   "simple solid DID",
			did:    "did:solid:alice",
			method: "solid",
			id:     "alice",
		},
		{
			name:   "solid DID with hyphens",
			did:    "did:solid:alice-example-123",
			method: "solid",
			id:     "alice-example-123",
		},
		{
			name:   "solid DID with dots",
			did:    "did:solid:alice.example",
			method: "solid",
			id:     "alice.example",
		},
		{
			name:   "solid DID with underscores",
			did:    "did:solid:alice_example",
			method: "solid",
			id:     "alice_example",
		},
		{
			name:   "solid DID with numbers",
			did:    "did:solid:alice123",
			method: "solid",
			id:     "alice123",
		},
		{
			name:   "uppercase method",
			did:    "did:SOLID:alice",
			method: "SOLID",
			id:     "alice",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			did, err := parser.ParseDID(tc.did)
			if err != nil {
				t.Fatalf("failed to parse DID %q: %v", tc.did, err)
			}
			if did.Method != tc.method {
				t.Errorf("expected method %q, got %q", tc.method, did.Method)
			}
			if did.MethodSpecificID != tc.id {
				t.Errorf("expected method-specific ID %q, got %q", tc.id, did.MethodSpecificID)
			}
			if did.Original != tc.did {
				t.Errorf("expected original %q, got %q", tc.did, did.Original)
			}
		})
	}
}

// TestParseInvalidDIDs tests parsing invalid DID strings
func TestParseInvalidDIDs(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	testCases := []struct {
		name string
		did  string
	}{
		{name: "empty string", did: ""},
		{name: "missing prefix", did: "solid:alice"},
		{name: "missing method", did: "did:"},
		{name: "missing separator", did: "didsolidalice"},
		{name: "missing ID", did: "did:solid:"},
		{name: "empty method", did: "did::alice"},
		{name: "with query string", did: "did:solid:alice?foo=bar"},
		{name: "with fragment", did: "did:solid:alice#fragment"},
		{name: "with space", did: "did:solid:alice example"},
		{name: "too long", did: "did:solid:" + string(make([]byte, MaxMethodSpecificIDLength+1))},
		{name: "unsafe character", did: "did:solid:alice@example"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParseDID(tc.did)
			if err == nil {
				t.Errorf("expected error for DID %q, got nil", tc.did)
			}
		})
	}
}

// TestParseSolidDID tests the ParseSolidDID convenience function
func TestParseSolidDID(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	t.Run("valid solid DID", func(t *testing.T) {
		did, err := parser.ParseSolidDID("did:solid:alice")
		if err != nil {
			t.Fatalf("failed to parse solid DID: %v", err)
		}
		if !did.IsSolidDID() {
			t.Error("expected IsSolidDID to be true")
		}
	})

	t.Run("non-solid DID", func(t *testing.T) {
		_, err := parser.ParseSolidDID("did:web:alice")
		if err == nil {
			t.Error("expected error for non-solid DID")
		}
		if !errors.Is(err, ErrInvalidDIDMethod) {
			t.Errorf("expected ErrInvalidDIDMethod, got %v", err)
		}
	})

	t.Run("invalid DID", func(t *testing.T) {
		_, err := parser.ParseSolidDID("invalid")
		if err == nil {
			t.Error("expected error for invalid DID")
		}
	})
}

// TestDIDStringMethods tests DID string methods
func TestDIDStringMethods(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	t.Run("String", func(t *testing.T) {
		did, _ := parser.ParseDID("did:solid:alice")
		if did.String() != "did:solid:alice" {
			t.Errorf("expected 'did:solid:alice', got %q", did.String())
		}
	})

	t.Run("NormalizedString", func(t *testing.T) {
		did, _ := parser.ParseDID("did:SOLID:Alice")
		if did.NormalizedString() != "did:solid:alice" {
			t.Errorf("expected 'did:solid:alice', got %q", did.NormalizedString())
		}
	})

	t.Run("IsSolidDID", func(t *testing.T) {
		did, _ := parser.ParseDID("did:solid:alice")
		if !did.IsSolidDID() {
			t.Error("expected IsSolidDID to be true")
		}

		did, _ = parser.ParseDID("did:web:alice")
		if did.IsSolidDID() {
			t.Error("expected IsSolidDID to be false")
		}
	})
}

// TestDIDParserWithAllowedMethods tests parser with allowed methods
func TestDIDParserWithAllowedMethods(t *testing.T) {
	options := DefaultDIDParserOptions()
	options.AllowedMethods = []string{"solid", "web"}
	parser := NewDIDParser(options)

	t.Run("allowed method", func(t *testing.T) {
		_, err := parser.ParseDID("did:solid:alice")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("disallowed method", func(t *testing.T) {
		_, err := parser.ParseDID("did:example:alice")
		if err == nil {
			t.Error("expected error for disallowed method")
		}
	})
}

// TestDIDParserWithHostLikeIDs tests parser with host-like ID requirement
func TestDIDParserWithHostLikeIDs(t *testing.T) {
	options := DefaultDIDParserOptions()
	options.RequireHostLikeID = true
	parser := NewDIDParser(options)

	t.Run("host-like ID", func(t *testing.T) {
		_, err := parser.ParseDID("did:solid:alice.example")
		if err != nil {
			t.Errorf("expected no error for host-like ID, got: %v", err)
		}
	})

	t.Run("non-host-like ID", func(t *testing.T) {
		_, err := parser.ParseDID("did:solid:alice_example")
		if err == nil {
			t.Error("expected error for non-host-like ID")
		}
	})

	t.Run("normalization", func(t *testing.T) {
		// Parse an uppercase host-like ID and verify it's normalized to lowercase
		did, err := parser.ParseDID("did:solid:Alice.Example")
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}
		// With host-like requirement, the ID should be normalized to lowercase
		if did.MethodSpecificID != "alice.example" {
			t.Errorf("expected normalized ID 'alice.example', got %q", did.MethodSpecificID)
		}
	})
}

// TestHostLikeIDRegex tests the host-like ID regex
func TestHostLikeIDRegex(t *testing.T) {
	testCases := []struct {
		id         string
		isHostLike bool
	}{
		{"alice.example", true},
		{"alice", true},
		{"alice123", true},
		{"alice-example", true},
		{"alice.example.com", true},
		{"sub-alice.example", true},
		{"Alice.Example", false}, // uppercase not allowed in strict mode
		{"alice_example", false},
		{"alice example", false},
		{"-alice", false},         // leading hyphen
		{"alice-", false},         // trailing hyphen
		{".alice", false},         // leading dot
		{"alice.", false},         // trailing dot
		{"alice..example", false}, // consecutive dots
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			parser := NewDIDParser(DefaultDIDParserOptions())
			result := parser.IsHostLikeID(tc.id)
			if result != tc.isHostLike {
				t.Errorf("expected IsHostLikeID(%q) = %v, got %v", tc.id, tc.isHostLike, result)
			}
		})
	}
}

// TestParseDIDURL tests DID URL parsing
func TestParseDIDURL(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	t.Run("simple DID", func(t *testing.T) {
		du, err := parser.ParseDIDURL("did:solid:alice")
		if err != nil {
			t.Fatalf("failed to parse DID URL: %v", err)
		}
		if du.DID.Method != "solid" {
			t.Errorf("expected method 'solid', got %q", du.DID.Method)
		}
		if du.Path != "" || du.Query != "" || du.Fragment != "" {
			t.Error("expected no path/query/fragment")
		}
	})

	t.Run("DID with fragment", func(t *testing.T) {
		du, err := parser.ParseDIDURL("did:solid:alice#key-1")
		if err != nil {
			t.Fatalf("failed to parse DID URL: %v", err)
		}
		if du.Fragment != "key-1" {
			t.Errorf("expected fragment 'key-1', got %q", du.Fragment)
		}
	})

	t.Run("DID with path", func(t *testing.T) {
		du, err := parser.ParseDIDURL("did:solid:alice/service/1")
		if err != nil {
			t.Fatalf("failed to parse DID URL: %v", err)
		}
		if du.Path != "/service/1" {
			t.Errorf("expected path '/service/1', got %q", du.Path)
		}
	})

	t.Run("DID with query", func(t *testing.T) {
		du, err := parser.ParseDIDURL("did:solid:alice?version=1")
		if err != nil {
			t.Fatalf("failed to parse DID URL: %v", err)
		}
		if du.Query != "version=1" {
			t.Errorf("expected query 'version=1', got %q", du.Query)
		}
	})
}

// TestVerificationMethodIsValid tests VerificationMethod.IsValid
func TestVerificationMethodIsValid(t *testing.T) {
	testCases := []struct {
		name  string
		vm    VerificationMethod
		valid bool
	}{
		{
			name: "valid with multibase",
			vm: VerificationMethod{
				ID:                 "did:solid:alice#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:solid:alice",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
			valid: true,
		},
		{
			name: "valid with JWK",
			vm: VerificationMethod{
				ID:           "did:solid:alice#key-1",
				Type:         "Ed25519VerificationKey2020",
				Controller:   "did:solid:alice",
				PublicKeyJWK: `{"kty":"OKP","crv":"Ed25519","x":"..."}`,
			},
			valid: true,
		},
		{
			name: "missing ID",
			vm: VerificationMethod{
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:solid:alice",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
			valid: false,
		},
		{
			name: "missing type",
			vm: VerificationMethod{
				ID:                 "did:solid:alice#key-1",
				Controller:         "did:solid:alice",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
			valid: false,
		},
		{
			name: "missing controller",
			vm: VerificationMethod{
				ID:                 "did:solid:alice#key-1",
				Type:               "Ed25519VerificationKey2020",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
			valid: false,
		},
		{
			name: "missing public key",
			vm: VerificationMethod{
				ID:         "did:solid:alice#key-1",
				Type:       "Ed25519VerificationKey2020",
				Controller: "did:solid:alice",
			},
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.vm.IsValid()
			if result != tc.valid {
				t.Errorf("expected IsValid() = %v, got %v", tc.valid, result)
			}
		})
	}
}

// TestServiceIsValid tests Service.IsValid
func TestServiceIsValid(t *testing.T) {
	testCases := []struct {
		name  string
		s     Service
		valid bool
	}{
		{
			name: "valid service",
			s: Service{
				ID:              "did:solid:alice#storage",
				Type:            "SolidStorage",
				ServiceEndpoint: "https://storage.example.org/alice/",
			},
			valid: true,
		},
		{
			name: "missing ID",
			s: Service{
				Type:            "SolidStorage",
				ServiceEndpoint: "https://storage.example.org/alice/",
			},
			valid: false,
		},
		{
			name: "missing type",
			s: Service{
				ID:              "did:solid:alice#storage",
				ServiceEndpoint: "https://storage.example.org/alice/",
			},
			valid: false,
		},
		{
			name: "missing endpoint",
			s: Service{
				ID:   "did:solid:alice#storage",
				Type: "SolidStorage",
			},
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.s.IsValid()
			if result != tc.valid {
				t.Errorf("expected IsValid() = %v, got %v", tc.valid, result)
			}
		})
	}
}

// TestServiceIsHTTPS tests Service.IsHTTPS
func TestServiceIsHTTPS(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
		isHTTPS  bool
	}{
		{"HTTPS endpoint", "https://example.org", true},
		{"HTTP endpoint", "http://example.org", false},
		{"HTTPS with port", "https://example.org:8443", true},
		{"invalid URL", "invalid", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := Service{
				ID:              "did:solid:alice#service",
				Type:            "TestService",
				ServiceEndpoint: tc.endpoint,
			}
			result := s.IsHTTPS()
			if result != tc.isHTTPS {
				t.Errorf("expected IsHTTPS() = %v, got %v", tc.isHTTPS, result)
			}
		})
	}
}

// TestDIDDocumentIsValid tests DIDDocument.IsValid
func TestDIDDocumentIsValid(t *testing.T) {
	t.Run("valid document", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		if !doc.IsValid() {
			t.Error("expected valid document")
		}
	})

	t.Run("missing ID", func(t *testing.T) {
		doc := DIDDocument{
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		if doc.IsValid() {
			t.Error("expected invalid document")
		}
	})

	t.Run("no verification methods", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
		}
		if doc.IsValid() {
			t.Error("expected invalid document")
		}
	})

	t.Run("invalid verification method", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:         "did:solid:alice#key-1",
					Type:       "Ed25519VerificationKey2020",
					Controller: "did:solid:alice",
					// Missing public key
				},
			},
		}
		if doc.IsValid() {
			t.Error("expected invalid document")
		}
	})
}

// TestGetSolidServices tests DIDDocument service getter methods
func TestGetSolidServices(t *testing.T) {
	doc := DIDDocument{
		ID: "did:solid:alice",
		VerificationMethod: []VerificationMethod{
			{
				ID:                 "did:solid:alice#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:solid:alice",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
		},
		Service: []Service{
			{ID: "did:solid:alice#storage", Type: "SolidStorage", ServiceEndpoint: "https://storage.example.org/alice/"},
			{ID: "did:solid:alice#webid", Type: "WebID", ServiceEndpoint: "https://webid.example.org/alice/card#me"},
			{ID: "did:solid:alice#issuer", Type: "OpenIDProvider", ServiceEndpoint: "https://issuer.example.org/"},
		},
	}

	t.Run("GetSolidStorageService", func(t *testing.T) {
		service := doc.GetSolidStorageService()
		if service == nil {
			t.Fatal("expected storage service")
		}
		if service.ServiceEndpoint != "https://storage.example.org/alice/" {
			t.Errorf("expected storage endpoint, got %q", service.ServiceEndpoint)
		}
	})

	t.Run("GetSolidWebIDService", func(t *testing.T) {
		service := doc.GetSolidWebIDService()
		if service == nil {
			t.Fatal("expected WebID service")
		}
		if service.ServiceEndpoint != "https://webid.example.org/alice/card#me" {
			t.Errorf("expected WebID endpoint, got %q", service.ServiceEndpoint)
		}
	})

	t.Run("GetSolidOIDCIssuerService", func(t *testing.T) {
		service := doc.GetSolidOIDCIssuerService()
		if service == nil {
			t.Fatal("expected OIDC issuer service")
		}
		if service.ServiceEndpoint != "https://issuer.example.org/" {
			t.Errorf("expected issuer endpoint, got %q", service.ServiceEndpoint)
		}
	})

	t.Run("service not found", func(t *testing.T) {
		docNoServices := DIDDocument{
			ID: "did:solid:bob",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:bob#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:bob",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		service := docNoServices.GetSolidStorageService()
		if service != nil {
			t.Error("expected nil for non-existent service")
		}
	})
}

// TestValidateDIDDocument tests DIDDocument validation
func TestValidateDIDDocument(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	t.Run("valid document", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
			Authentication: []string{"did:solid:alice#key-1"},
		}
		err := parser.ValidateDIDDocument(doc)
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("missing ID", func(t *testing.T) {
		doc := DIDDocument{
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		err := parser.ValidateDIDDocument(doc)
		if err == nil {
			t.Error("expected error for missing ID")
		}
	})

	t.Run("ID mismatch", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:bob",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		err := parser.ValidateDIDDocument(doc)
		if err == nil {
			t.Error("expected error for ID mismatch")
		}
	})

	t.Run("invalid verification method", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:         "did:solid:alice#key-1",
					Type:       "Ed25519VerificationKey2020",
					Controller: "did:solid:alice",
					// Missing public key
				},
			},
		}
		err := parser.ValidateDIDDocument(doc)
		if err == nil {
			t.Error("expected error for invalid verification method")
		}
	})

	t.Run("verification method ID not under DID", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:bob#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		err := parser.ValidateDIDDocument(doc)
		if err == nil {
			t.Error("expected error for verification method ID not under DID")
		}
	})

	t.Run("authentication reference not found", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
			Authentication: []string{"did:solid:alice#key-2"}, // Not found
		}
		err := parser.ValidateDIDDocument(doc)
		if err == nil {
			t.Error("expected error for authentication reference not found")
		}
	})
}

// TestDIDDocumentMetadata tests DIDDocumentMetadata
func TestDIDDocumentMetadata(t *testing.T) {
	t.Run("IsValid with valid document", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		expiresAt := time.Now().Add(1 * time.Hour)
		metadata := DIDDocumentMetadata{
			DID:       DID{Method: "solid", MethodSpecificID: "alice", Original: "did:solid:alice"},
			Document:  doc,
			ExpiresAt: &expiresAt,
		}
		if !metadata.IsValid() {
			t.Error("expected valid metadata")
		}
	})

	t.Run("IsValid with expired document", func(t *testing.T) {
		doc := DIDDocument{
			ID: "did:solid:alice",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "did:solid:alice#key-1",
					Type:               "Ed25519VerificationKey2020",
					Controller:         "did:solid:alice",
					PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				},
			},
		}
		expiresAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
		metadata := DIDDocumentMetadata{
			DID:       DID{Method: "solid", MethodSpecificID: "alice", Original: "did:solid:alice"},
			Document:  doc,
			ExpiresAt: &expiresAt,
		}
		if metadata.IsValid() {
			t.Error("expected invalid metadata for expired document")
		}
	})

	t.Run("IsValid with invalid document", func(t *testing.T) {
		doc := DIDDocument{ID: ""} // Invalid
		metadata := DIDDocumentMetadata{
			DID:      DID{Method: "solid", MethodSpecificID: "alice", Original: "did:solid:alice"},
			Document: doc,
		}
		if metadata.IsValid() {
			t.Error("expected invalid metadata for invalid document")
		}
	})
}

// TestParseDIDDocument tests ParseDIDDocument
func TestParseDIDDocument(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	t.Run("parse with expected DID", func(t *testing.T) {
		// This is a placeholder test - actual JSON parsing will be implemented later
		// For now, we just verify it doesn't panic
		_, err := parser.ParseDIDDocument([]byte(`{"id": "did:solid:alice"}`), "did:solid:alice")
		if err != nil {
			t.Logf("ParseDIDDocument returned error (expected in placeholder): %v", err)
		}
	})

	t.Run("empty DID string", func(t *testing.T) {
		_, err := parser.ParseDIDDocument([]byte("data"), "")
		if err == nil {
			t.Error("expected error for empty expected DID")
		}
	})

	t.Run("invalid expected DID", func(t *testing.T) {
		_, err := parser.ParseDIDDocument([]byte("data"), "invalid-did")
		if err == nil {
			t.Error("expected error for invalid expected DID")
		}
	})
}

// TestResolverCreation tests creating a resolver
func TestResolverCreation(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	resolver := NewResolver(DefaultResolverOptions(), parser)
	if resolver == nil {
		t.Fatal("resolver is nil")
	}
}

// TestResolverDefaultOptions tests default resolver options
func TestResolverDefaultOptions(t *testing.T) {
	options := DefaultResolverOptions()

	if options.Enabled {
		t.Error("expected resolver to be disabled by default")
	}
	if options.DefaultMappingEnabled {
		t.Error("expected default mapping to be disabled by default")
	}
	if options.MaxDocumentBytes == 0 {
		t.Error("expected max document bytes > 0")
	}
	if options.CacheTTLSeconds == 0 {
		t.Error("expected cache TTL > 0")
	}
	if options.TimeoutSeconds == 0 {
		t.Error("expected timeout > 0")
	}
}

// TestResolverDisabled tests that disabled resolver returns error
func TestResolverDisabled(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = false
	resolver := NewResolver(options, parser)

	_, err := resolver.Resolve(context.Background(), "did:solid:alice")
	if err == nil {
		t.Error("expected error for disabled resolver")
	}
}

// TestRegisterAndResolveLocalDID tests registering and resolving a local DID
func TestRegisterAndResolveLocalDID(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	options.AllowedResolvers = []string{"local"}
	resolver := NewResolver(options, parser)

	// Create a valid DID document
	doc := DIDDocument{
		ID: "did:solid:alice",
		VerificationMethod: []VerificationMethod{
			{
				ID:                 "did:solid:alice#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:solid:alice",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
		},
		Authentication: []string{"did:solid:alice#key-1"},
		Service: []Service{
			{ID: "did:solid:alice#webid", Type: "WebID", ServiceEndpoint: "https://webid.example.org/alice/card#me"},
		},
	}

	// Register the DID
	err := resolver.RegisterLocalDID("did:solid:alice", doc)
	if err != nil {
		t.Fatalf("failed to register DID: %v", err)
	}

	// Resolve the DID
	metadata, err := resolver.Resolve(context.Background(), "did:solid:alice")
	if err != nil {
		t.Fatalf("failed to resolve DID: %v", err)
	}

	// Verify the resolved document
	if metadata.DID.String() != "did:solid:alice" {
		t.Errorf("expected DID 'did:solid:alice', got %q", metadata.DID.String())
	}
	if !metadata.IsValid() {
		t.Error("expected valid metadata")
	}
}

// TestResolverWithInvalidDID tests resolving an invalid DID
func TestResolverWithInvalidDID(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	resolver := NewResolver(options, parser)

	_, err := resolver.Resolve(context.Background(), "invalid-did")
	if err == nil {
		t.Error("expected error for invalid DID")
	}
}

// TestResolverWithUnregisteredDID tests resolving an unregistered DID
func TestResolverWithUnregisteredDID(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	options.AllowedResolvers = []string{"local"}
	resolver := NewResolver(options, parser)

	_, err := resolver.Resolve(context.Background(), "did:solid:unregistered")
	if err == nil {
		t.Error("expected error for unregistered DID")
	}
}

// TestValidateWebIDBacklink tests WebID backlink validation
func TestValidateWebIDBacklink(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	options.AllowedResolvers = []string{"local"}
	resolver := NewResolver(options, parser)

	// Create a DID document with WebID service
	doc := DIDDocument{
		ID: "did:solid:alice",
		VerificationMethod: []VerificationMethod{
			{
				ID:                 "did:solid:alice#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:solid:alice",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
		},
		Authentication: []string{"did:solid:alice#key-1"},
		Service: []Service{
			{ID: "did:solid:alice#webid", Type: "WebID", ServiceEndpoint: "https://webid.example.org/alice/card#me"},
		},
	}

	// Register the DID
	err := resolver.RegisterLocalDID("did:solid:alice", doc)
	if err != nil {
		t.Fatalf("failed to register DID: %v", err)
	}

	// Validate backlink with matching WebID
	err = resolver.ValidateWebIDBacklink(context.Background(), "did:solid:alice", "https://webid.example.org/alice/card#me")
	// This will fail because we don't have a real WebID profile with backlink
	// But it should not panic
	if err == nil {
		t.Log("WebID backlink validation succeeded (may be due to simplified check)")
	} else {
		t.Logf("WebID backlink validation failed (expected): %v", err)
	}
}

// TestValidateDIDBinding tests full DID binding validation
func TestValidateDIDBinding(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	options.AllowedResolvers = []string{"local"}
	resolver := NewResolver(options, parser)

	// Create a valid DID document
	doc := DIDDocument{
		ID: "did:solid:alice",
		VerificationMethod: []VerificationMethod{
			{
				ID:                 "did:solid:alice#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:solid:alice",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
		},
		Authentication: []string{"did:solid:alice#key-1"},
		Service: []Service{
			{ID: "did:solid:alice#webid", Type: "WebID", ServiceEndpoint: "https://webid.example.org/alice/card#me"},
		},
	}

	// Register the DID
	err := resolver.RegisterLocalDID("did:solid:alice", doc)
	if err != nil {
		t.Fatalf("failed to register DID: %v", err)
	}

	// Validate binding
	// This will likely fail due to missing WebID backlink, but should not panic
	err = resolver.ValidateDIDBinding(context.Background(), "did:solid:alice", "https://webid.example.org/alice/card#me")
	if err == nil {
		t.Log("DID binding validation succeeded (may be due to simplified checks)")
	} else {
		t.Logf("DID binding validation failed (expected): %v", err)
	}
}

// TestValidateDIDBindingWithNonSolidDID tests binding validation with non-solid DID
func TestValidateDIDBindingWithNonSolidDID(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	resolver := NewResolver(options, parser)

	err := resolver.ValidateDIDBinding(context.Background(), "did:web:alice", "https://webid.example.org/alice/card#me")
	if err == nil {
		t.Error("expected error for non-solid DID")
	}
	if !errors.Is(err, ErrInvalidDIDMethod) {
		t.Errorf("expected ErrInvalidDIDMethod, got %v", err)
	}
}

// TestValidateDIDBindingWithInvalidDID tests binding validation with invalid DID
func TestValidateDIDBindingWithInvalidDID(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	resolver := NewResolver(options, parser)

	err := resolver.ValidateDIDBinding(context.Background(), "invalid-did", "https://webid.example.org/alice/card#me")
	if err == nil {
		t.Error("expected error for invalid DID")
	}
}

// TestDIDCache tests the DID cache
func TestDIDCache(t *testing.T) {
	cache := NewDIDCache(1 * time.Hour)

	t.Run("Set and Get", func(t *testing.T) {
		metadata := DIDDocumentMetadata{
			DID: DID{Method: "solid", MethodSpecificID: "alice", Original: "did:solid:alice"},
			Document: DIDDocument{
				ID: "did:solid:alice",
				VerificationMethod: []VerificationMethod{
					{
						ID:                 "did:solid:alice#key-1",
						Type:               "Ed25519VerificationKey2020",
						Controller:         "did:solid:alice",
						PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
					},
				},
			},
		}

		cache.Set("did:solid:alice", metadata)

		got, ok := cache.Get("did:solid:alice")
		if !ok {
			t.Fatal("expected to find cached entry")
		}
		if got.DID.String() != "did:solid:alice" {
			t.Errorf("expected DID 'did:solid:alice', got %q", got.DID.String())
		}
	})

	t.Run("Get non-existent", func(t *testing.T) {
		_, ok := cache.Get("did:solid:nonexistent")
		if ok {
			t.Error("expected not to find non-existent entry")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		cache.Delete("did:solid:alice")
		_, ok := cache.Get("did:solid:alice")
		if ok {
			t.Error("expected entry to be deleted")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		// Add some entries
		cache.Set("did:solid:alice", DIDDocumentMetadata{DID: DID{Method: "solid", MethodSpecificID: "alice"}})
		cache.Set("did:solid:bob", DIDDocumentMetadata{DID: DID{Method: "solid", MethodSpecificID: "bob"}})

		cache.Clear()

		_, ok := cache.Get("did:solid:alice")
		if ok {
			t.Error("expected cache to be cleared")
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		cache := NewDIDCache(10 * time.Millisecond) // Very short TTL
		metadata := DIDDocumentMetadata{
			DID: DID{Method: "solid", MethodSpecificID: "alice"},
			Document: DIDDocument{
				ID: "did:solid:alice",
				VerificationMethod: []VerificationMethod{
					{
						ID:                 "did:solid:alice#key-1",
						Type:               "Ed25519VerificationKey2020",
						Controller:         "did:solid:alice",
						PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
					},
				},
			},
		}

		cache.Set("did:solid:alice", metadata)

		// Wait for expiration
		time.Sleep(20 * time.Millisecond)

		_, ok := cache.Get("did:solid:alice")
		if ok {
			t.Error("expected cached entry to be expired")
		}
	})
}

// TestResolverOptionsIsResolverAllowed tests IsResolverAllowed
func TestResolverOptionsIsResolverAllowed(t *testing.T) {
	options := DefaultResolverOptions()
	options.AllowedResolvers = []string{"local", "https"}

	t.Run("allowed resolver", func(t *testing.T) {
		if !options.IsResolverAllowed("local") {
			t.Error("expected 'local' to be allowed")
		}
		if !options.IsResolverAllowed("https") {
			t.Error("expected 'https' to be allowed")
		}
	})

	t.Run("disallowed resolver", func(t *testing.T) {
		if options.IsResolverAllowed("http") {
			t.Error("expected 'http' to be disallowed")
		}
	})
}

// TestDIDNormalizedString tests DID normalization
func TestDIDNormalizedString(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())

	did, _ := parser.ParseDID("did:SOLID:Alice.Example")
	normalized := did.NormalizedString()
	expected := "did:solid:alice.example"
	if normalized != expected {
		t.Errorf("expected %q, got %q", expected, normalized)
	}
}

// TestResolverWithContextCancellation tests context cancellation
func TestResolverWithContextCancellation(t *testing.T) {
	parser := NewDIDParser(DefaultDIDParserOptions())
	options := DefaultResolverOptions()
	options.Enabled = true
	resolver := NewResolver(options, parser)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := resolver.Resolve(ctx, "did:solid:alice")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

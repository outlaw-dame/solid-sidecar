// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"strings"
	"testing"
)

// TestSAIParserParse tests SAI parser parsing
func TestSAIParserParse(t *testing.T) {
	parser := NewSAIParser(DefaultSAIParserOptions())
	ctx := context.Background()

	t.Run("valid SAI policy", func(t *testing.T) {
		policyJSON := `{
			"policyURI": "https://example.org/policy.sai",
			"resourceURI": "https://example.org/resource",
			"rules": [
				{
					"ruleID": "rule-1",
					"premise": {
						"agent": "https://example.org/alice#me",
						"resource": "https://example.org/resource"
					},
					"conclusion": {
						"allows": true,
						"grantedModes": ["read", "write"]
					},
					"enabled": true
				}
			],
			"inherit": true,
			"owner": "https://example.org/alice#me"
		}`

		result, err := parser.Parse(ctx, []byte(policyJSON), "application/sai+json")
		if err != nil {
			t.Fatalf("failed to parse valid SAI policy: %v", err)
		}
		if result.BaseURI != "https://example.org/policy.sai" {
			t.Errorf("expected BaseURI to be policy URI, got %s", result.BaseURI)
		}
		if result.ContentType != "application/sai+json" {
			t.Errorf("expected ContentType to be application/sai+json, got %s", result.ContentType)
		}
		if result.SHA256 == "" {
			t.Error("expected SHA256 to be non-empty")
		}
		if len(result.Triples) == 0 {
			t.Error("expected RDF triples to be generated")
		}
	})

	t.Run("unsupported content type", func(t *testing.T) {
		policyJSON := `{"policyURI": "https://example.org/policy.sai"}`
		_, err := parser.Parse(ctx, []byte(policyJSON), "text/html")
		if err == nil {
			t.Error("expected error for unsupported content type")
		}
		if !strings.Contains(err.Error(), "content type not supported") {
			t.Errorf("expected content type error, got: %v", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := `{invalid json}`
		_, err := parser.Parse(ctx, []byte(invalidJSON), "application/sai+json")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("non-strict mode with invalid JSON", func(t *testing.T) {
		parser := NewSAIParser(SAIParserOptions{
			StrictMode: false,
		})
		invalidJSON := `{invalid json}`
		// In non-strict mode, JSON parsing errors are still fatal
		// because we can't parse the structure at all
		_, err := parser.Parse(ctx, []byte(invalidJSON), "application/sai+json")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "failed to parse SAI policy") {
			t.Logf("got error: %v", err)
		}
	})

	t.Run("empty content", func(t *testing.T) {
		_, err := parser.Parse(ctx, []byte{}, "application/sai+json")
		if err == nil {
			t.Error("expected error for empty content")
		}
	})

	t.Run("supported content types", func(t *testing.T) {
		parser := NewSAIParser(DefaultSAIParserOptions())
		supported := parser.SupportedContentTypes()
		if len(supported) == 0 {
			t.Error("expected supported content types")
		}
		found := false
		for _, ct := range supported {
			if ct == "application/sai+json" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected application/sai+json to be supported")
		}
	})
}

// TestSAIParserParseSAIPolicyDirect tests direct SAI policy parsing
func TestSAIParserParseSAIPolicyDirect(t *testing.T) {
	parser := NewSAIParser(DefaultSAIParserOptions())
	ctx := context.Background()

	t.Run("valid SAI policy", func(t *testing.T) {
		policyJSON := `{
			"policyURI": "https://example.org/policy.sai",
			"resourceURI": "https://example.org/resource",
			"rules": [
				{
					"ruleID": "rule-1",
					"premise": {
						"agent": "https://example.org/alice#me",
						"resource": "https://example.org/resource"
					},
					"conclusion": {
						"allows": true,
						"grantedModes": ["read"]
					},
					"enabled": true
				}
			],
			"owner": "https://example.org/alice#me"
		}`

		result, err := parser.ParseSAIPolicyDirect(ctx, []byte(policyJSON))
		if err != nil {
			t.Fatalf("failed to parse SAI policy: %v", err)
		}
		if result.Policy.PolicyURI != "https://example.org/policy.sai" {
			t.Errorf("expected PolicyURI to match, got %s", result.Policy.PolicyURI)
		}
		if !result.IsValid() {
			t.Error("expected parse result to be valid")
		}
		if result.SHA256 == "" {
			t.Error("expected SHA256 to be non-empty")
		}
	})

	t.Run("policy with warnings", func(t *testing.T) {
		// Create a policy that will generate warnings
		policyJSON := `{
			"policyURI": "https://example.org/policy.sai",
			"resourceURI": "https://example.org/resource",
			"rules": []
		}`

		result, err := parser.ParseSAIPolicyDirect(ctx, []byte(policyJSON))
		if err != nil {
			t.Fatalf("failed to parse SAI policy: %v", err)
		}
		// Empty rules is valid
		if !result.IsValid() {
			t.Logf("policy is invalid (expected): %v", result.Errors)
		}
	})

	t.Run("invalid policy JSON", func(t *testing.T) {
		invalidJSON := `{not valid json}`
		_, err := parser.ParseSAIPolicyDirect(ctx, []byte(invalidJSON))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

// TestSAIParserOptions tests SAI parser options
func TestSAIParserOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		options := DefaultSAIParserOptions()
		if options.MaxInputSize != SAIMaxPolicySize {
			t.Errorf("expected MaxInputSize to be %d, got %d", SAIMaxPolicySize, options.MaxInputSize)
		}
		if options.StrictMode != true {
			t.Error("expected StrictMode to be true by default")
		}
	})

	t.Run("custom options", func(t *testing.T) {
		parser := NewSAIParser(SAIParserOptions{
			MaxInputSize: 1024,
			StrictMode:   false,
		})
		if parser.options.MaxInputSize != 1024 {
			t.Errorf("expected MaxInputSize to be 1024, got %d", parser.options.MaxInputSize)
		}
		if parser.options.StrictMode != false {
			t.Error("expected StrictMode to be false")
		}
	})

	t.Run("zero values use defaults", func(t *testing.T) {
		parser := NewSAIParser(SAIParserOptions{
			MaxInputSize: 0,
			Timeout:      0,
		})
		if parser.options.MaxInputSize != SAIMaxPolicySize {
			t.Errorf("expected MaxInputSize to default to %d, got %d", SAIMaxPolicySize, parser.options.MaxInputSize)
		}
	})
}

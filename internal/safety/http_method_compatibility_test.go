package safety

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTPMethodCompatibility_Fixtures tests that all standard HTTP methods
// pass through the safety validation without being rejected.
// This ensures the sidecar does not break standard HTTP method usage.
func TestHTTPMethodCompatibility_Fixtures(t *testing.T) {
	// All standard HTTP methods that should be supported
	methods := []string{
		"GET",
		"HEAD",
		"OPTIONS",
		"PUT",
		"POST",
		"PATCH",
		"DELETE",
		"CONNECT",
		"TRACE",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/resource", nil)
			if err := ValidateRequest(req); err != nil {
				t.Errorf("method %s was rejected: %v", method, err)
			}
		})
	}
}

// TestHTTPMethodCompatibility_WithBodies tests that methods with bodies
// are handled correctly.
func TestHTTPMethodCompatibility_WithBodies(t *testing.T) {
	body := []byte("test content")
	methodsWithBody := []string{"PUT", "POST", "PATCH"}

	for _, method := range methodsWithBody {
		t.Run(method+" with body", func(t *testing.T) {
			req := httptest.NewRequest(method, "/resource", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/ld+json")
			if err := ValidateRequest(req); err != nil {
				t.Errorf("method %s with body was rejected: %v", method, err)
			}
		})
	}
}

// TestHTTPMethodCompatibility_WithValidSolidContentTypes tests that
// Solid-specific content types work with all write methods.
func TestHTTPMethodCompatibility_WithValidSolidContentTypes(t *testing.T) {
	writeMethods := []string{"PUT", "POST", "PATCH"}
	solidContentTypes := []string{
		"text/turtle",
		"application/ld+json",
		"application/n-triples",
		"application/rdf+xml",
	}

	for _, method := range writeMethods {
		for _, ct := range solidContentTypes {
			t.Run(method+" with "+ct, func(t *testing.T) {
				req := httptest.NewRequest(method, "/resource", nil)
				req.Header.Set("Content-Type", ct)
				if err := ValidateRequest(req); err != nil {
					t.Errorf("method %s with Content-Type %s was rejected: %v", method, ct, err)
				}
			})
		}
	}
}

// TestHTTPMethodCompatibility_ReadOnlyMethods tests that read-only methods
// work correctly without content-type validation.
func TestHTTPMethodCompatibility_ReadOnlyMethods(t *testing.T) {
	readOnlyMethods := []string{"GET", "HEAD", "OPTIONS"}

	for _, method := range readOnlyMethods {
		t.Run(method, func(t *testing.T) {
			// These methods shouldn't require Content-Type
			req := httptest.NewRequest(method, "/resource", nil)
			if err := ValidateRequest(req); err != nil {
				t.Errorf("read-only method %s was rejected: %v", method, err)
			}

			// And they should work with any Content-Type (though unusual)
			req = httptest.NewRequest(method, "/resource", nil)
			req.Header.Set("Content-Type", "text/html")
			if err := ValidateRequest(req); err != nil {
				t.Errorf("read-only method %s with text/html was rejected: %v", method, err)
			}
		})
	}
}

// TestHTTPMethodCompatibility_EdgeCases tests edge cases for HTTP method handling.
func TestHTTPMethodCompatibility_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		contentType string
		wantErr     bool
	}{
		{
			name:        "PUT with valid LD+JSON",
			method:      "PUT",
			contentType: "application/ld+json",
			wantErr:     false,
		},
		{
			name:        "POST with valid Turtle",
			method:      "POST",
			contentType: "text/turtle",
			wantErr:     false,
		},
		{
			name:        "PATCH with valid RDF/XML",
			method:      "PATCH",
			contentType: "application/rdf+xml",
			wantErr:     false,
		},
		{
			name:        "DELETE with no content type",
			method:      "DELETE",
			contentType: "",
			wantErr:     false,
		},
		{
			name:        "GET with disallowed content type",
			method:      "GET",
			contentType: "text/html",
			wantErr:     false, // GET doesn't care about content-type
		},
		{
			name:        "PUT with disallowed text/html",
			method:      "PUT",
			contentType: "text/html",
			wantErr:     true,
		},
		{
			name:        "POST with disallowed javascript",
			method:      "POST",
			contentType: "text/javascript",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/resource", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			err := ValidateRequest(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

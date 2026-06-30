package safety

import (
	"net/http/httptest"
	"testing"
)

func TestIsWriteMethod(t *testing.T) {
	tests := []struct {
		method  string
		isWrite bool
		desc    string
	}{
		{"GET", false, "GET is read-only"},
		{"HEAD", false, "HEAD is read-only"},
		{"OPTIONS", false, "OPTIONS is read-only"},
		{"PUT", true, "PUT is write"},
		{"POST", true, "POST is write"},
		{"PATCH", true, "PATCH is write"},
		{"DELETE", true, "DELETE is write"},
		{"put", true, "case insensitive: put"},
		{"POST", true, "case insensitive: POST"},
		{"Unknown", false, "unknown method is not write"},
		{"", false, "empty method is not write"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := IsWriteMethod(tt.method)
			if result != tt.isWrite {
				t.Errorf("IsWriteMethod(%q) = %v, want %v", tt.method, result, tt.isWrite)
			}
		})
	}
}

func TestValidateWriteRequest_AllowedMethods(t *testing.T) {
	// Non-write methods should always pass
	nonWriteMethods := []string{"GET", "HEAD", "OPTIONS"}
	for _, method := range nonWriteMethods {
		t.Run(method+" passes", func(t *testing.T) {
			req := httptest.NewRequest(method, "/resource", nil)
			if err := ValidateWriteRequest(req); err != nil {
				t.Errorf("ValidateWriteRequest(%s) = %v, want nil", method, err)
			}
		})
	}
}

func TestValidateWriteRequest_AllowedContentTypes(t *testing.T) {
	allowedTypes := []string{
		"text/turtle",
		"application/ld+json",
		"application/json",
		"application/n-triples",
		"application/rdf+xml",
		"application/sparql-results+json",
		"application/octet-stream",
		"multipart/form-data",
		// With charset parameters
		"application/ld+json; charset=utf-8",
		"text/turtle; charset=utf-8",
		// Case variations
		"Application/Ld+Json",
		"TEXT/TURTLE",
	}

	for _, ct := range allowedTypes {
		t.Run(ct, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/resource", nil)
			req.Header.Set("Content-Type", ct)
			if err := ValidateWriteRequest(req); err != nil {
				t.Errorf("ValidateWriteRequest with Content-Type %q = %v, want nil", ct, err)
			}
		})
	}
}

func TestValidateWriteRequest_DisallowedContentTypes(t *testing.T) {
	disallowedTypes := []string{
		"text/html",
		"text/javascript",
		"application/javascript",
		"application/x-javascript",
		"application/ecmascript",
	}

	for _, ct := range disallowedTypes {
		t.Run(ct, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/resource", nil)
			req.Header.Set("Content-Type", ct)
			if err := ValidateWriteRequest(req); err == nil {
				t.Errorf("ValidateWriteRequest with disallowed Content-Type %q = nil, want error", ct)
			}
		})
	}
}

func TestValidateWriteRequest_NoContentType(t *testing.T) {
	// No Content-Type header should pass through
	req := httptest.NewRequest("PUT", "/resource", nil)
	if err := ValidateWriteRequest(req); err != nil {
		t.Errorf("ValidateWriteRequest with no Content-Type = %v, want nil", err)
	}
}

func TestValidateWriteRequest_UnknownContentType(t *testing.T) {
	// Unknown content types should pass through for CSS compatibility
	unknownTypes := []string{
		"application/xml",
		"text/plain",
		"custom/type",
	}

	for _, ct := range unknownTypes {
		t.Run(ct, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/resource", nil)
			req.Header.Set("Content-Type", ct)
			if err := ValidateWriteRequest(req); err != nil {
				t.Errorf("ValidateWriteRequest with unknown Content-Type %q = %v, want nil", ct, err)
			}
		})
	}
}

func TestValidateWriteRequest_DELETE(t *testing.T) {
	// DELETE requests should pass regardless of Content-Type
	req := httptest.NewRequest("DELETE", "/resource", nil)
	req.Header.Set("Content-Type", "text/html") // Would be disallowed for other methods
	if err := ValidateWriteRequest(req); err != nil {
		t.Errorf("ValidateWriteRequest(DELETE with text/html) = %v, want nil", err)
	}
}

func TestValidateWriteRequest_WhitespaceInContentType(t *testing.T) {
	// Should handle whitespace gracefully
	req := httptest.NewRequest("PUT", "/resource", nil)
	req.Header.Set("Content-Type", "  application/ld+json  ")
	if err := ValidateWriteRequest(req); err != nil {
		t.Errorf("ValidateWriteRequest with whitespace in Content-Type = %v, want nil", err)
	}
}

func TestValidateMethodTarget(t *testing.T) {
	// Currently a placeholder, should always pass
	req := httptest.NewRequest("PUT", "/resource", nil)
	if err := ValidateMethodTarget(req); err != nil {
		t.Errorf("ValidateMethodTarget = %v, want nil", err)
	}
}
